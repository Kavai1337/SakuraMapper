#include "pe_mapper.h"
#include <fstream>
#include <cstring>
#include <cstdio>

namespace sakura {

    bool PeMapper::load_dll(const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return false;

        auto size = file.tellg();
        if (size < sizeof(DosHeader)) return false;

        raw_dll_.resize(static_cast<size_t>(size));
        file.seekg(0);
        file.read(reinterpret_cast<char*>(raw_dll_.data()), size);
        file.close();

        return validate_pe();
    }

    bool PeMapper::validate_pe() {
        if (raw_dll_.size() < sizeof(DosHeader)) return false;

        dos_hdr_ = reinterpret_cast<const DosHeader*>(raw_dll_.data());
        if (dos_hdr_->e_magic != DOS_MAGIC) return false;

        if (static_cast<size_t>(dos_hdr_->e_lfanew) + sizeof(NtHeaders64) > raw_dll_.size())
            return false;

        nt_hdr_ = reinterpret_cast<const NtHeaders64*>(raw_dll_.data() + dos_hdr_->e_lfanew);
        if (nt_hdr_->Signature != NT_SIGNATURE) return false;
        if (nt_hdr_->OptionalHeader.Magic != OPTIONAL_HDR64_MAGIC) return false;
        if (nt_hdr_->FileHeader.Machine != MACHINE_AMD64) return false;

        sections_ = reinterpret_cast<const SectionHeader*>(
            reinterpret_cast<const uint8_t*>(&nt_hdr_->OptionalHeader) +
            nt_hdr_->FileHeader.SizeOfOptionalHeader
        );

        return true;
    }

    bool PeMapper::map_sections(std::vector<uint8_t>& mapped) {
        uint32_t image_size = nt_hdr_->OptionalHeader.SizeOfImage;
        mapped.resize(image_size, 0);

        uint32_t headers_size = nt_hdr_->OptionalHeader.SizeOfHeaders;
        if (headers_size > raw_dll_.size()) return false;
        memcpy(mapped.data(), raw_dll_.data(), headers_size);

        for (uint16_t i = 0; i < nt_hdr_->FileHeader.NumberOfSections; i++) {
            const auto& sec = sections_[i];
            if (sec.SizeOfRawData == 0) continue;

            if (sec.PointerToRawData + sec.SizeOfRawData > raw_dll_.size()) return false;

            uint32_t copy_size = sec.SizeOfRawData;
            if (sec.VirtualSize > 0 && sec.SizeOfRawData > sec.VirtualSize) {
                copy_size = sec.VirtualSize;
            }

            if (sec.VirtualAddress + copy_size > image_size) return false;

            memcpy(
                mapped.data() + sec.VirtualAddress,
                raw_dll_.data() + sec.PointerToRawData,
                copy_size
            );
        }

        return true;
    }

    bool PeMapper::apply_relocations(std::vector<uint8_t>& mapped, uint64_t target_base) {
        const auto& reloc_dir = nt_hdr_->OptionalHeader.DataDirectories[DIR_BASERELOC];
        if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0) {
            return true;
        }

        int64_t delta = static_cast<int64_t>(target_base) -
                        static_cast<int64_t>(nt_hdr_->OptionalHeader.ImageBase);

        if (delta == 0) return true;

        uint32_t reloc_rva = reloc_dir.VirtualAddress;
        uint32_t reloc_end = reloc_rva + reloc_dir.Size;

        while (reloc_rva < reloc_end) {
            if (reloc_rva + sizeof(BaseRelocation) > mapped.size()) return false;

            auto* block = reinterpret_cast<const BaseRelocation*>(mapped.data() + reloc_rva);
            if (block->SizeOfBlock == 0) break;
            if (block->SizeOfBlock < sizeof(BaseRelocation)) return false;

            uint32_t entry_count = (block->SizeOfBlock - sizeof(BaseRelocation)) / sizeof(uint16_t);
            auto* entries = reinterpret_cast<const uint16_t*>(
                mapped.data() + reloc_rva + sizeof(BaseRelocation)
            );

            for (uint32_t i = 0; i < entry_count; i++) {
                uint16_t type   = entries[i] >> 12;
                uint16_t offset = entries[i] & 0x0FFF;

                if (type == RELOC_ABSOLUTE) continue;

                if (type == RELOC_DIR64) {
                    uint32_t target_rva = block->VirtualAddress + offset;
                    if (target_rva + sizeof(uint64_t) > mapped.size()) return false;

                    uint64_t* ptr = reinterpret_cast<uint64_t*>(mapped.data() + target_rva);
                    *ptr += delta;
                } else {
                    return false;
                }
            }

            reloc_rva += block->SizeOfBlock;
        }

        return true;
    }

    bool PeMapper::collect_imports(const std::vector<uint8_t>& mapped, std::vector<ImportEntry>& imports) {
        const auto& import_dir = nt_hdr_->OptionalHeader.DataDirectories[DIR_IMPORT];
        if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) return true;

        uint32_t desc_rva = import_dir.VirtualAddress;

        while (true) {
            if (desc_rva + sizeof(ImportDescriptor) > mapped.size()) break;

            auto* desc = reinterpret_cast<const ImportDescriptor*>(mapped.data() + desc_rva);
            if (desc->Name == 0 && desc->FirstThunk == 0) break;

            if (desc->Name >= mapped.size()) return false;
            const char* dll_name = reinterpret_cast<const char*>(mapped.data() + desc->Name);

            uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            uint32_t iat_rva   = desc->FirstThunk;

            while (true) {
                if (thunk_rva + sizeof(uint64_t) > mapped.size()) break;

                uint64_t thunk_data = *reinterpret_cast<const uint64_t*>(mapped.data() + thunk_rva);
                if (thunk_data == 0) break;

                ImportEntry entry = {};
                strncpy(entry.dll_name, dll_name, sizeof(entry.dll_name) - 1);
                entry.iat_rva = iat_rva;

                if (thunk_data & ORDINAL_FLAG64) {
                    entry.is_ordinal = 1;
                    entry.ordinal = static_cast<uint16_t>(thunk_data & 0xFFFF);
                } else {
                    uint32_t name_rva = static_cast<uint32_t>(thunk_data);
                    if (name_rva + sizeof(ImportByName) <= mapped.size()) {
                        auto* hint_name = reinterpret_cast<const ImportByName*>(mapped.data() + name_rva);
                        strncpy(entry.func_name, hint_name->Name, sizeof(entry.func_name) - 1);
                        entry.ordinal = hint_name->Hint;
                        entry.is_ordinal = 0;
                    }
                }

                imports.push_back(entry);

                thunk_rva += sizeof(uint64_t);
                iat_rva   += sizeof(uint64_t);
            }

            desc_rva += sizeof(ImportDescriptor);
        }

        return true;
    }

    void PeMapper::collect_exception_info(const std::vector<uint8_t>& mapped, uint32_t& rva, uint32_t& count) {
        rva = 0;
        count = 0;

        const auto& exc_dir = nt_hdr_->OptionalHeader.DataDirectories[DIR_EXCEPTION];
        if (exc_dir.VirtualAddress == 0 || exc_dir.Size == 0) return;

        rva = exc_dir.VirtualAddress;
        count = exc_dir.Size / 12;

        printf("[Mapper] Exception directory: RVA=0x%X, %u entries\n", rva, count);
    }

    void PeMapper::collect_tls_callbacks(const std::vector<uint8_t>& mapped, uint64_t target_base, std::vector<uint32_t>& callback_rvas) {
        const auto& tls_dir = nt_hdr_->OptionalHeader.DataDirectories[DIR_TLS];
        if (tls_dir.VirtualAddress == 0 || tls_dir.Size == 0) return;

        if (tls_dir.VirtualAddress + sizeof(TlsDirectory64) > mapped.size()) return;

        auto* tls = reinterpret_cast<const TlsDirectory64*>(mapped.data() + tls_dir.VirtualAddress);

        uint64_t callbacks_va = tls->AddressOfCallBacks;
        if (callbacks_va == 0) return;

        uint32_t callbacks_rva = static_cast<uint32_t>(callbacks_va - target_base);
        if (callbacks_rva + sizeof(uint64_t) > mapped.size()) return;

        const uint64_t* cb_array = reinterpret_cast<const uint64_t*>(mapped.data() + callbacks_rva);
        while (true) {
            if (reinterpret_cast<const uint8_t*>(cb_array) + sizeof(uint64_t) > mapped.data() + mapped.size())
                break;

            uint64_t cb_va = *cb_array;
            if (cb_va == 0) break;

            uint32_t cb_rva = static_cast<uint32_t>(cb_va - target_base);
            callback_rvas.push_back(cb_rva);
            printf("[Mapper] TLS callback at RVA 0x%X\n", cb_rva);

            cb_array++;
        }
    }

    void PeMapper::strip_reloc(std::vector<uint8_t>& mapped) {
        auto* mapped_nt = reinterpret_cast<NtHeaders64*>(
            mapped.data() + reinterpret_cast<const DosHeader*>(mapped.data())->e_lfanew
        );
        auto* mapped_sections = reinterpret_cast<SectionHeader*>(
            reinterpret_cast<uint8_t*>(&mapped_nt->OptionalHeader) +
            mapped_nt->FileHeader.SizeOfOptionalHeader
        );

        for (uint16_t i = 0; i < mapped_nt->FileHeader.NumberOfSections; i++) {
            char name[9] = {};
            memcpy(name, mapped_sections[i].Name, 8);
            if (strcmp(name, ".reloc") == 0) {
                uint32_t va   = mapped_sections[i].VirtualAddress;
                uint32_t size = mapped_sections[i].VirtualSize;
                if (va + size <= mapped.size()) {
                    for (uint32_t j = 0; j < size; j++) {
                        mapped[va + j] = static_cast<uint8_t>((j * 0x41 + 0x7F) & 0xFF);
                    }
                }

                uint32_t raw_size = mapped_sections[i].SizeOfRawData;
                if (raw_size > size && va + raw_size <= mapped.size()) {
                    for (uint32_t j = size; j < raw_size; j++) {
                        mapped[va + j] = static_cast<uint8_t>((j * 0x37 + 0x5A) & 0xFF);
                    }
                }

                memset(mapped_sections[i].Name, 0, 8);
                mapped_sections[i].VirtualSize      = 0;
                mapped_sections[i].SizeOfRawData    = 0;
                mapped_sections[i].PointerToRawData = 0;
                mapped_sections[i].Characteristics  = 0;

                printf("[Mapper] Stripped .reloc section (%u bytes)\n", size);
                break;
            }
        }

        mapped_nt->OptionalHeader.DataDirectories[DIR_BASERELOC].VirtualAddress = 0;
        mapped_nt->OptionalHeader.DataDirectories[DIR_BASERELOC].Size = 0;
        mapped_nt->OptionalHeader.DllCharacteristics &= ~0x0040;
    }

    void PeMapper::strip_debug(std::vector<uint8_t>& mapped) {
        auto* mapped_nt = reinterpret_cast<NtHeaders64*>(
            mapped.data() + reinterpret_cast<const DosHeader*>(mapped.data())->e_lfanew
        );

        mapped_nt->OptionalHeader.DataDirectories[DIR_DEBUG].VirtualAddress = 0;
        mapped_nt->OptionalHeader.DataDirectories[DIR_DEBUG].Size = 0;
    }

    MappedImage PeMapper::map(uint64_t target_base) {
        MappedImage result = {};

        if (raw_dll_.empty() || !nt_hdr_) {
            result.error = "No DLL loaded";
            return result;
        }

        if (!map_sections(result.image)) {
            result.error = "Failed to map sections";
            return result;
        }

        if (!apply_relocations(result.image, target_base)) {
            result.error = "Failed to apply relocations";
            return result;
        }

        if (!collect_imports(result.image, result.imports)) {
            result.error = "Failed to collect imports";
            return result;
        }

        collect_exception_info(result.image, result.exception_dir_rva, result.exception_dir_count);
        collect_tls_callbacks(result.image, target_base, result.tls_callback_rvas);

        strip_reloc(result.image);
        strip_debug(result.image);

        result.entry_point_rva   = nt_hdr_->OptionalHeader.AddressOfEntryPoint;
        result.original_image_base = nt_hdr_->OptionalHeader.ImageBase;
        result.relocated_base    = target_base;
        result.success           = true;

        return result;
    }

} // namespace sakura
