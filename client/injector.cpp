#include "injector.h"
#include <cstdio>
#include <cstring>
#include <set>
#include <TlHelp32.h>

namespace sakura {

bool Injector::allocate(HANDLE process, uint32_t image_size, uint64_t& out_base) {
    void* alloc = VirtualAllocEx(
        process, nullptr, image_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );

    if (!alloc) return false;
    out_base = reinterpret_cast<uint64_t>(alloc);
    return true;
}

static bool resolve_imports_locally(
    uint8_t* image,
    uint32_t image_size,
    const std::vector<ImportEntry>& imports,
    HANDLE target_process
) {
    std::set<std::string> loaded_dlls;

    for (const auto& imp : imports) {
        std::string dll(imp.dll_name);
        if (loaded_dlls.count(dll)) continue;
        loaded_dlls.insert(dll);

        HMODULE hMod = GetModuleHandleA(imp.dll_name);
        if (!hMod) {
            HMODULE k32 = GetModuleHandleA("kernel32.dll");
            auto pLoadLib = GetProcAddress(k32, "LoadLibraryA");

            void* remote_str = VirtualAllocEx(target_process, nullptr, 256,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!remote_str) {
                printf("[Injector] Failed to alloc for DLL name: %s\n", imp.dll_name);
                return false;
            }

            WriteProcessMemory(target_process, remote_str, imp.dll_name,
                             strlen(imp.dll_name) + 1, nullptr);

            HANDLE thread = CreateRemoteThread(
                target_process, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLib),
                remote_str, 0, nullptr
            );

            if (thread) {
                WaitForSingleObject(thread, 5000);
                CloseHandle(thread);
            }

            VirtualFreeEx(target_process, remote_str, 0, MEM_RELEASE);
            LoadLibraryA(imp.dll_name);
        }
    }

    for (const auto& imp : imports) {
        HMODULE hMod = GetModuleHandleA(imp.dll_name);
        if (!hMod) {
            printf("[Injector] Module not found: %s\n", imp.dll_name);
            return false;
        }

        FARPROC func = nullptr;
        if (imp.is_ordinal) {
            func = GetProcAddress(hMod, MAKEINTRESOURCEA(imp.ordinal));
        } else {
            func = GetProcAddress(hMod, imp.func_name);
        }

        if (!func) {
            printf("[Injector] Function not found: %s!%s\n",
                   imp.dll_name, imp.is_ordinal ? "(ordinal)" : imp.func_name);
            return false;
        }

        if (imp.iat_rva + sizeof(uint64_t) > image_size) {
            printf("[Injector] IAT RVA out of bounds: 0x%X\n", imp.iat_rva);
            return false;
        }

        uint64_t addr = reinterpret_cast<uint64_t>(func);
        memcpy(image + imp.iat_rva, &addr, sizeof(uint64_t));

        printf("[Injector]   %s!%s -> 0x%llX (IAT @ 0x%X)\n",
               imp.dll_name,
               imp.is_ordinal ? "(ordinal)" : imp.func_name,
               static_cast<unsigned long long>(addr),
               imp.iat_rva);
    }

    return true;
}

static void emit_mov_rcx_imm64(std::vector<uint8_t>& code, uint64_t val) {
    code.push_back(0x48); code.push_back(0xB9);
    for (int i = 0; i < 8; i++) code.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
}

static void emit_mov_rdx_imm64(std::vector<uint8_t>& code, uint64_t val) {
    code.push_back(0x48); code.push_back(0xBA);
    for (int i = 0; i < 8; i++) code.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
}

static void emit_mov_edx_imm32(std::vector<uint8_t>& code, uint32_t val) {
    code.push_back(0xBA);
    for (int i = 0; i < 4; i++) code.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
}

static void emit_mov_r8_imm64(std::vector<uint8_t>& code, uint64_t val) {
    code.push_back(0x49); code.push_back(0xB8);
    for (int i = 0; i < 8; i++) code.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
}

static void emit_xor_r8_r8(std::vector<uint8_t>& code) {
    code.push_back(0x4D); code.push_back(0x33); code.push_back(0xC0);
}

static void emit_mov_rax_imm64(std::vector<uint8_t>& code, uint64_t val) {
    code.push_back(0x48); code.push_back(0xB8);
    for (int i = 0; i < 8; i++) code.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
}

static void emit_call_rax(std::vector<uint8_t>& code) {
    code.push_back(0xFF); code.push_back(0xD0);
}

static void emit_sub_rsp(std::vector<uint8_t>& code, uint8_t val) {
    code.push_back(0x48); code.push_back(0x83); code.push_back(0xEC); code.push_back(val);
}

static void emit_add_rsp(std::vector<uint8_t>& code, uint8_t val) {
    code.push_back(0x48); code.push_back(0x83); code.push_back(0xC4); code.push_back(val);
}

static void emit_ret(std::vector<uint8_t>& code) {
    code.push_back(0xC3);
}

std::vector<uint8_t> Injector::build_shellcode(
    uint64_t image_base,
    uint32_t entry_point_rva,
    uint64_t fn_RtlAddFunctionTable,
    uint64_t pdata_addr,
    uint32_t pdata_count,
    const std::vector<uint64_t>& tls_callback_addrs
) {
    std::vector<uint8_t> code;
    code.reserve(512);

    emit_sub_rsp(code, 0x28);

    if (pdata_count > 0 && fn_RtlAddFunctionTable != 0) {
        emit_mov_rcx_imm64(code, pdata_addr);
        emit_mov_edx_imm32(code, pdata_count);
        emit_mov_r8_imm64(code, image_base);
        emit_mov_rax_imm64(code, fn_RtlAddFunctionTable);
        emit_call_rax(code);
        printf("[Injector] Shellcode: RtlAddFunctionTable(%u entries)\n", pdata_count);
    }

    for (size_t i = 0; i < tls_callback_addrs.size(); i++) {
        emit_mov_rcx_imm64(code, image_base);
        emit_mov_edx_imm32(code, 1);
        emit_xor_r8_r8(code);
        emit_mov_rax_imm64(code, tls_callback_addrs[i]);
        emit_call_rax(code);
        printf("[Injector] Shellcode: TLS callback #%zu\n", i);
    }

    uint64_t entry_addr = image_base + entry_point_rva;
    emit_mov_rcx_imm64(code, image_base);
    emit_mov_edx_imm32(code, 1);
    emit_xor_r8_r8(code);
    emit_mov_rax_imm64(code, entry_addr);
    emit_call_rax(code);

    emit_add_rsp(code, 0x28);
    emit_ret(code);

    return code;
}

InjectionResult Injector::inject(
    HANDLE process,
    uint64_t remote_base,
    const uint8_t* image,
    uint32_t image_size,
    uint32_t entry_point_rva,
    const std::vector<ImportEntry>& imports,
    uint32_t exception_dir_rva,
    uint32_t exception_dir_count,
    const std::vector<uint32_t>& tls_callback_rvas
) {
    InjectionResult result = {};

    std::vector<uint8_t> patched_image(image, image + image_size);

    printf("[Injector] Resolving %zu imports...\n", imports.size());
    if (!resolve_imports_locally(patched_image.data(), image_size, imports, process)) {
        result.error = "Failed to resolve imports";
        return result;
    }
    printf("[Injector] All imports resolved\n");

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, reinterpret_cast<void*>(remote_base),
                           patched_image.data(), image_size, &written)) {
        result.error = "WriteProcessMemory failed for image";
        return result;
    }
    printf("[Injector] Wrote %zu bytes of mapped image at 0x%llX\n",
           written, static_cast<unsigned long long>(remote_base));

    uint64_t fn_RtlAddFunctionTable = 0;
    if (exception_dir_count > 0) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            fn_RtlAddFunctionTable = reinterpret_cast<uint64_t>(
                GetProcAddress(ntdll, "RtlAddFunctionTable"));
        }
        if (!fn_RtlAddFunctionTable) {
            HMODULE k32 = GetModuleHandleA("kernel32.dll");
            if (k32) {
                fn_RtlAddFunctionTable = reinterpret_cast<uint64_t>(
                    GetProcAddress(k32, "RtlAddFunctionTable"));
            }
        }
        if (fn_RtlAddFunctionTable) {
            printf("[Injector] RtlAddFunctionTable at 0x%llX\n",
                   static_cast<unsigned long long>(fn_RtlAddFunctionTable));
        } else {
            printf("[Injector] WARNING: RtlAddFunctionTable not found, SEH won't work\n");
        }
    }

    std::vector<uint64_t> tls_abs;
    for (uint32_t rva : tls_callback_rvas) {
        tls_abs.push_back(remote_base + rva);
    }
    if (!tls_abs.empty()) {
        printf("[Injector] %zu TLS callbacks to call\n", tls_abs.size());
    }

    uint64_t pdata_addr = (exception_dir_rva > 0) ? (remote_base + exception_dir_rva) : 0;
    auto shellcode = build_shellcode(
        remote_base,
        entry_point_rva,
        fn_RtlAddFunctionTable,
        pdata_addr,
        exception_dir_count,
        tls_abs
    );

    printf("[Injector] Shellcode size: %zu bytes\n", shellcode.size());

    void* code_mem = VirtualAllocEx(
        process, nullptr, shellcode.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if (!code_mem) {
        result.error = "VirtualAllocEx failed for shellcode";
        return result;
    }

    if (!WriteProcessMemory(process, code_mem, shellcode.data(), shellcode.size(), &written)) {
        result.error = "WriteProcessMemory failed for shellcode";
        return result;
    }

    uint64_t entry_addr = remote_base + entry_point_rva;
    printf("[Injector] Shellcode at 0x%p (DllMain=0x%llX)\n",
           code_mem, static_cast<unsigned long long>(entry_addr));

    HANDLE thread = CreateRemoteThread(
        process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(code_mem),
        nullptr, 0, nullptr
    );

    if (!thread) {
        result.error = "CreateRemoteThread failed (error " + std::to_string(GetLastError()) + ")";
        return result;
    }

    printf("[Injector] Remote thread created, waiting...\n");
    WaitForSingleObject(thread, 10000);

    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    CloseHandle(thread);

    printf("[Injector] Thread exited with code: %lu\n", exit_code);

    result.success = true;
    result.remote_base = remote_base;
    return result;
}

} // namespace sakura
