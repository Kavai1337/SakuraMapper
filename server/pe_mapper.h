#pragma once
#include "../shared/pe_defs.h"
#include "../shared/protocol.h"
#include <vector>
#include <string>
#include <cstdint>

namespace sakura {

struct MappedImage {
    std::vector<uint8_t>      image;
    uint32_t                  entry_point_rva;
    uint64_t                  original_image_base;
    uint64_t                  relocated_base;
    std::vector<ImportEntry>  imports;
    uint32_t                  exception_dir_rva;
    uint32_t                  exception_dir_count;
    std::vector<uint32_t>     tls_callback_rvas;
    bool                      success;
    std::string               error;
};

class PeMapper {
public:
    bool load_dll(const std::string& path);
    MappedImage map(uint64_t target_base);

private:
    bool validate_pe();
    bool map_sections(std::vector<uint8_t>& mapped);
    bool apply_relocations(std::vector<uint8_t>& mapped, uint64_t target_base);
    bool collect_imports(const std::vector<uint8_t>& mapped, std::vector<ImportEntry>& imports);
    void collect_exception_info(const std::vector<uint8_t>& mapped, uint32_t& rva, uint32_t& count);
    void collect_tls_callbacks(const std::vector<uint8_t>& mapped, uint64_t target_base, std::vector<uint32_t>& callback_rvas);
    void strip_reloc(std::vector<uint8_t>& mapped);
    void strip_debug(std::vector<uint8_t>& mapped);

    std::vector<uint8_t> raw_dll_;
    const DosHeader*     dos_hdr_ = nullptr;
    const NtHeaders64*   nt_hdr_  = nullptr;
    const SectionHeader* sections_ = nullptr;
};

} // namespace sakura
