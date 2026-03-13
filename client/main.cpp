#include "ws_client.h"
#include "hwid.h"
#include "injector.h"
#include "../shared/protocol.h"
#include "../shared/crypto.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <TlHelp32.h>

static DWORD find_process(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

int main(int argc, char* argv[]) {
    std::string server_host = "127.0.0.1";
    uint16_t    server_port = 9150;
    std::string license_key;
    std::string target_process;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            server_host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            server_port = static_cast<uint16_t>(atoi(argv[++i]));
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            license_key = argv[++i];
        else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc)
            target_process = argv[++i];
    }

    if (license_key.empty()) {
        char buf[128];
        printf("License key: ");
        fgets(buf, sizeof(buf), stdin);
        buf[strcspn(buf, "\r\n")] = '\0';
        license_key = buf;
    }

    if (target_process.empty()) {
        char buf[128];
        printf("Target process name (e.g. notepad.exe): ");
        fgets(buf, sizeof(buf), stdin);
        buf[strcspn(buf, "\r\n")] = '\0';
        target_process = buf;
    }

    std::string hwid = sakura::generate_hwid();
    printf("[Client] HWID: %s\n", hwid.c_str());

    DWORD target_pid = find_process(target_process.c_str());
    if (target_pid == 0) {
        printf("[Client] Process '%s' not found!\n", target_process.c_str());
        return 1;
    }
    printf("[Client] Found %s (PID: %lu)\n", target_process.c_str(), target_pid);

    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, target_pid
    );
    if (!hProcess) {
        printf("[Client] Failed to open process (error %lu). Run as admin?\n", GetLastError());
        return 1;
    }

    printf("[Client] Connecting to %s:%d...\n", server_host.c_str(), server_port);
    sakura::WsClient ws;
    if (!ws.connect(server_host, server_port)) {
        printf("[Client] Failed to connect to server!\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[Client] Connected\n");

    sakura::AuthRequest auth = {};
    strncpy(auth.license_key, license_key.c_str(), sizeof(auth.license_key) - 1);
    strncpy(auth.hwid, hwid.c_str(), sizeof(auth.hwid) - 1);

    auto auth_pkt = sakura::make_packet(sakura::PacketType::AUTH_REQUEST, &auth, sizeof(auth));
    if (!ws.send_binary(auth_pkt)) {
        printf("[Client] Failed to send auth request!\n");
        CloseHandle(hProcess);
        return 1;
    }

    std::vector<uint8_t> response;
    if (!ws.recv_binary(response)) {
        printf("[Client] Failed to receive auth response!\n");
        CloseHandle(hProcess);
        return 1;
    }

    if (response.size() < sizeof(sakura::PacketHeader)) {
        printf("[Client] Invalid response!\n");
        CloseHandle(hProcess);
        return 1;
    }

    auto* resp_hdr = reinterpret_cast<const sakura::PacketHeader*>(response.data());

    if (resp_hdr->type == sakura::PacketType::AUTH_FAIL) {
        auto* fail = reinterpret_cast<const sakura::AuthFailResponse*>(
            response.data() + sizeof(sakura::PacketHeader));
        printf("[Client] Auth failed: %s\n", fail->reason);
        CloseHandle(hProcess);
        return 1;
    }

    if (resp_hdr->type != sakura::PacketType::AUTH_OK) {
        printf("[Client] Unexpected response type: 0x%02X\n", static_cast<int>(resp_hdr->type));
        CloseHandle(hProcess);
        return 1;
    }

    auto* auth_ok = reinterpret_cast<const sakura::AuthOkResponse*>(
        response.data() + sizeof(sakura::PacketHeader));
    uint32_t image_size = auth_ok->image_size;
    printf("[Client] Auth OK, image size: %u bytes\n", image_size);

    sakura::Injector injector;
    uint64_t remote_base = 0;
    if (!injector.allocate(hProcess, image_size, remote_base)) {
        printf("[Client] Failed to allocate memory in target process!\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[Client] Allocated at 0x%llX in target\n",
           static_cast<unsigned long long>(remote_base));

    sakura::MapRequest map_req = {};
    map_req.target_base = remote_base;
    auto map_pkt = sakura::make_packet(sakura::PacketType::MAP_REQUEST, &map_req, sizeof(map_req));
    if (!ws.send_binary(map_pkt)) {
        printf("[Client] Failed to send map request!\n");
        CloseHandle(hProcess);
        return 1;
    }

    printf("[Client] Waiting for mapped image...\n");
    std::vector<uint8_t> map_response;
    if (!ws.recv_binary(map_response)) {
        printf("[Client] Failed to receive map response!\n");
        CloseHandle(hProcess);
        return 1;
    }

    auto* map_hdr = reinterpret_cast<const sakura::PacketHeader*>(map_response.data());
    if (map_hdr->type == sakura::PacketType::MAP_ERROR) {
        auto* err = reinterpret_cast<const sakura::AuthFailResponse*>(
            map_response.data() + sizeof(sakura::PacketHeader));
        printf("[Client] Map error: %s\n", err->reason);
        CloseHandle(hProcess);
        return 1;
    }

    if (map_hdr->type != sakura::PacketType::MAP_RESPONSE) {
        printf("[Client] Unexpected response type: 0x%02X\n", static_cast<int>(map_hdr->type));
        CloseHandle(hProcess);
        return 1;
    }

    const uint8_t* payload = map_response.data() + sizeof(sakura::PacketHeader);
    auto* map_resp = reinterpret_cast<const sakura::MapResponseHeader*>(payload);

    printf("[Client] Received mapped image:\n");
    printf("  Image size:   %u\n", map_resp->image_size);
    printf("  Entry RVA:    0x%X\n", map_resp->entry_point_rva);
    printf("  Image base:   0x%llX\n", static_cast<unsigned long long>(map_resp->image_base));
    printf("  Imports:      %u\n", map_resp->import_count);
    printf("  Exceptions:   %u entries (RVA 0x%X)\n", map_resp->exception_dir_count, map_resp->exception_dir_rva);
    printf("  TLS callbacks: %u\n", map_resp->tls_callback_count);

    const uint8_t* read_ptr = payload + sizeof(sakura::MapResponseHeader);

    const sakura::ImportEntry* import_data = reinterpret_cast<const sakura::ImportEntry*>(read_ptr);
    std::vector<sakura::ImportEntry> imports(
        import_data, import_data + map_resp->import_count);
    read_ptr += map_resp->import_count * sizeof(sakura::ImportEntry);

    const sakura::TlsCallbackEntry* tls_data = reinterpret_cast<const sakura::TlsCallbackEntry*>(read_ptr);
    std::vector<uint32_t> tls_callback_rvas;
    for (uint32_t i = 0; i < map_resp->tls_callback_count; i++) {
        tls_callback_rvas.push_back(tls_data[i].callback_rva);
    }
    read_ptr += map_resp->tls_callback_count * sizeof(sakura::TlsCallbackEntry);

    const uint8_t* encrypted_image = read_ptr;

    std::vector<uint8_t> decrypted_image(encrypted_image, encrypted_image + map_resp->image_size);

    std::string transit_key = sakura::derive_transit_key(license_key, hwid);
    sakura::RC4::decrypt(decrypted_image.data(), decrypted_image.size(), transit_key);
    printf("[Client] Image decrypted\n");

    auto inject_result = injector.inject(
        hProcess,
        remote_base,
        decrypted_image.data(),
        map_resp->image_size,
        map_resp->entry_point_rva,
        imports,
        map_resp->exception_dir_rva,
        map_resp->exception_dir_count,
        tls_callback_rvas
    );

    if (!inject_result.success) {
        printf("[Client] Injection failed: %s\n", inject_result.error.c_str());
        CloseHandle(hProcess);
        return 1;
    }

    printf("[Client] Injection successful!\n");

    ws.disconnect();
    CloseHandle(hProcess);
    return 0;
}
