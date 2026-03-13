#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace sakura {

enum class PacketType : uint8_t {
    AUTH_REQUEST   = 0x01,
    AUTH_OK        = 0x02,
    AUTH_FAIL      = 0x03,
    MAP_REQUEST    = 0x10,
    MAP_RESPONSE   = 0x11,
    MAP_ERROR      = 0x12,
};

#pragma pack(push, 1)

struct PacketHeader {
    PacketType type;
    uint32_t   payload_size;
};

struct AuthRequest {
    char     license_key[64];
    char     hwid[64];
};

struct AuthOkResponse {
    uint32_t image_size;
};

struct AuthFailResponse {
    char reason[256];
};

struct MapRequest {
    uint64_t target_base;
};

struct ImportEntry {
    char     dll_name[128];
    char     func_name[128];
    uint16_t ordinal;
    uint8_t  is_ordinal;
    uint32_t iat_rva;
};

struct TlsCallbackEntry {
    uint32_t callback_rva;
};

struct MapResponseHeader {
    uint32_t image_size;
    uint32_t entry_point_rva;
    uint64_t image_base;
    uint32_t import_count;
    uint32_t exception_dir_rva;
    uint32_t exception_dir_count;
    uint32_t tls_callback_count;
};

#pragma pack(pop)

inline std::vector<uint8_t> make_packet(PacketType type, const void* data, uint32_t size) {
    std::vector<uint8_t> buf(sizeof(PacketHeader) + size);
    auto* hdr = reinterpret_cast<PacketHeader*>(buf.data());
    hdr->type = type;
    hdr->payload_size = size;
    if (data && size > 0) {
        memcpy(buf.data() + sizeof(PacketHeader), data, size);
    }
    return buf;
}

} // namespace sakura
