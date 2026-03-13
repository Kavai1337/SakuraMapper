#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include "../shared/protocol.h"
#include <vector>
#include <cstdint>
#include <string>

namespace sakura {

struct InjectionResult {
    bool        success;
    std::string error;
    uint64_t    remote_base;
};

class Injector {
public:
    bool allocate(HANDLE process, uint32_t image_size, uint64_t& out_base);

    InjectionResult inject(
        HANDLE process,
        uint64_t remote_base,
        const uint8_t* image,
        uint32_t image_size,
        uint32_t entry_point_rva,
        const std::vector<ImportEntry>& imports,
        uint32_t exception_dir_rva,
        uint32_t exception_dir_count,
        const std::vector<uint32_t>& tls_callback_rvas
    );

private:
    std::vector<uint8_t> build_shellcode(
        uint64_t image_base,
        uint32_t entry_point_rva,
        uint64_t fn_RtlAddFunctionTable,
        uint64_t pdata_addr,
        uint32_t pdata_count,
        const std::vector<uint64_t>& tls_callback_addrs
    );
};

} // namespace sakura
