#include "ws_server.h"
#include "pe_mapper.h"
#include "license_manager.h"
#include "../shared/protocol.h"
#include "../shared/crypto.h"
#include <cstdio>
#include <string>
#include <cstring>
#include <unordered_map>
#include <mutex>

static sakura::PeMapper       g_mapper;
static sakura::LicenseManager g_license;

struct ClientState {
    bool   authenticated = false;
    std::string license_key;
    std::string hwid;
};

static std::unordered_map<SOCKET, ClientState> g_clients;
static std::mutex g_clients_mtx;

static void send_fail(sakura::WsServer& server, SOCKET client, const char* reason) {
    sakura::AuthFailResponse resp = {};
    strncpy(resp.reason, reason, sizeof(resp.reason) - 1);
    auto pkt = sakura::make_packet(sakura::PacketType::AUTH_FAIL, &resp, sizeof(resp));
    server.send_binary(client, pkt);
}

static void handle_message(sakura::WsServer& server, SOCKET client, const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(sakura::PacketHeader)) {
        printf("[Server] Packet too small\n");
        return;
    }

    auto* hdr = reinterpret_cast<const sakura::PacketHeader*>(data.data());
    const uint8_t* payload = data.data() + sizeof(sakura::PacketHeader);
    uint32_t payload_size = hdr->payload_size;

    if (sizeof(sakura::PacketHeader) + payload_size > data.size()) {
        printf("[Server] Invalid packet size\n");
        return;
    }

    switch (hdr->type) {
    case sakura::PacketType::AUTH_REQUEST: {
        if (payload_size < sizeof(sakura::AuthRequest)) {
            send_fail(server, client, "Invalid auth packet");
            return;
        }

        auto* auth = reinterpret_cast<const sakura::AuthRequest*>(payload);
        std::string key(auth->license_key);
        std::string hwid(auth->hwid);

        printf("[Server] Auth request: key=%s hwid=%s\n", key.c_str(), hwid.c_str());

        std::string error = g_license.validate(key, hwid);
        if (!error.empty()) {
            printf("[Server] Auth failed: %s\n", error.c_str());
            send_fail(server, client, error.c_str());
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_clients_mtx);
            g_clients[client] = {true, key, hwid};
        }

        uint32_t image_size = static_cast<uint32_t>(g_mapper.map(0x180000000ULL).image.size());
        sakura::AuthOkResponse resp = {};
        resp.image_size = image_size;
        auto pkt = sakura::make_packet(sakura::PacketType::AUTH_OK, &resp, sizeof(resp));
        server.send_binary(client, pkt);

        printf("[Server] Auth OK, image_size=%u\n", image_size);
        break;
    }

    case sakura::PacketType::MAP_REQUEST: {
        ClientState state;
        {
            std::lock_guard<std::mutex> lock(g_clients_mtx);
            auto it = g_clients.find(client);
            if (it == g_clients.end() || !it->second.authenticated) {
                send_fail(server, client, "Not authenticated");
                return;
            }
            state = it->second;
        }

        if (payload_size < sizeof(sakura::MapRequest)) {
            send_fail(server, client, "Invalid map request");
            return;
        }

        auto* req = reinterpret_cast<const sakura::MapRequest*>(payload);
        printf("[Server] Map request: target_base=0x%llX\n",
               static_cast<unsigned long long>(req->target_base));

        auto result = g_mapper.map(req->target_base);
        if (!result.success) {
            printf("[Server] Mapping failed: %s\n", result.error.c_str());

            sakura::AuthFailResponse fail = {};
            strncpy(fail.reason, result.error.c_str(), sizeof(fail.reason) - 1);
            auto pkt = sakura::make_packet(sakura::PacketType::MAP_ERROR, &fail, sizeof(fail));
            server.send_binary(client, pkt);
            return;
        }

        printf("[Server] Mapping complete: %zu bytes, %zu imports, %u pdata entries, %zu TLS callbacks, entry=0x%X\n",
               result.image.size(), result.imports.size(),
               result.exception_dir_count, result.tls_callback_rvas.size(),
               result.entry_point_rva);

        sakura::MapResponseHeader resp_hdr = {};
        resp_hdr.image_size          = static_cast<uint32_t>(result.image.size());
        resp_hdr.entry_point_rva     = result.entry_point_rva;
        resp_hdr.image_base          = result.relocated_base;
        resp_hdr.import_count        = static_cast<uint32_t>(result.imports.size());
        resp_hdr.exception_dir_rva   = result.exception_dir_rva;
        resp_hdr.exception_dir_count = result.exception_dir_count;
        resp_hdr.tls_callback_count  = static_cast<uint32_t>(result.tls_callback_rvas.size());

        size_t total_payload = sizeof(resp_hdr)
            + result.imports.size() * sizeof(sakura::ImportEntry)
            + result.tls_callback_rvas.size() * sizeof(sakura::TlsCallbackEntry)
            + result.image.size();

        std::vector<uint8_t> response_data(sizeof(sakura::PacketHeader) + total_payload);
        auto* pkt_hdr = reinterpret_cast<sakura::PacketHeader*>(response_data.data());
        pkt_hdr->type = sakura::PacketType::MAP_RESPONSE;
        pkt_hdr->payload_size = static_cast<uint32_t>(total_payload);

        uint8_t* write_ptr = response_data.data() + sizeof(sakura::PacketHeader);

        memcpy(write_ptr, &resp_hdr, sizeof(resp_hdr));
        write_ptr += sizeof(resp_hdr);

        if (!result.imports.empty()) {
            memcpy(write_ptr, result.imports.data(),
                   result.imports.size() * sizeof(sakura::ImportEntry));
            write_ptr += result.imports.size() * sizeof(sakura::ImportEntry);
        }

        for (uint32_t rva : result.tls_callback_rvas) {
            sakura::TlsCallbackEntry entry = {};
            entry.callback_rva = rva;
            memcpy(write_ptr, &entry, sizeof(entry));
            write_ptr += sizeof(entry);
        }

        std::string transit_key = sakura::derive_transit_key(state.license_key, state.hwid);
        sakura::RC4::encrypt(result.image.data(), result.image.size(), transit_key);

        memcpy(write_ptr, result.image.data(), result.image.size());

        server.send_binary(client, response_data);
        printf("[Server] Sent mapped image (encrypted)\n");
        break;
    }

    default:
        printf("[Server] Unknown packet type: 0x%02X\n", static_cast<int>(hdr->type));
        break;
    }
}

int main(int argc, char* argv[]) {
    std::string dll_path = "payload.dll";
    uint16_t port = 9150;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dll") == 0 && i + 1 < argc) {
            dll_path = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = static_cast<uint16_t>(atoi(argv[++i]));
        }
    }

    printf("[Server] Loading DLL: %s\n", dll_path.c_str());
    if (!g_mapper.load_dll(dll_path)) {
        printf("[Server] Failed to load DLL!\n");
        return 1;
    }
    printf("[Server] DLL loaded successfully\n");

    if (!g_license.load("keys.json")) {
        printf("[Server] Failed to load license keys!\n");
        return 1;
    }
    printf("[Server] License keys loaded\n");

    sakura::WsServer server;
    server.set_on_message([&](SOCKET client, const std::vector<uint8_t>& data) {
        handle_message(server, client, data);
    });

    if (!server.start(port)) {
        printf("[Server] Failed to start on port %d!\n", port);
        return 1;
    }

    printf("[Server] Listening on ws://0.0.0.0:%d\n", port);
    printf("[Server] Press Enter to quit...\n");
    getchar();

    server.stop();

    {
        std::lock_guard<std::mutex> lock(g_clients_mtx);
        g_clients.clear();
    }

    return 0;
}
