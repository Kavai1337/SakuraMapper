#include "hwid.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <intrin.h>
#include <cstdio>

namespace sakura {

    std::string generate_hwid() {
        uint64_t hash = 0xcbf29ce484222325ULL;

        auto fnv_update = [&](const void* data, size_t len) {
            auto* bytes = static_cast<const uint8_t*>(data);
            for (size_t i = 0; i < len; i++) {
                hash ^= bytes[i];
                hash *= 0x100000001b3ULL;
            }
        };

        int cpu_info[4] = {};
        __cpuid(cpu_info, 0);
        fnv_update(cpu_info, sizeof(cpu_info));
        __cpuid(cpu_info, 1);
        fnv_update(cpu_info, sizeof(cpu_info));

        DWORD volume_serial = 0;
        GetVolumeInformationA("C:\\", nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0);
        fnv_update(&volume_serial, sizeof(volume_serial));

        char comp_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD comp_size = sizeof(comp_name);
        GetComputerNameA(comp_name, &comp_size);
        fnv_update(comp_name, comp_size);

        char buf[17];
        snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(hash));
        return std::string(buf);
    }

} // namespace sakura
