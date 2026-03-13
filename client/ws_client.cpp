#include "ws_client.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>

namespace sakura {

WsClient::WsClient() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    srand(static_cast<unsigned>(time(nullptr)));
}

WsClient::~WsClient() {
    disconnect();
    WSACleanup();
}

bool WsClient::connect(const std::string& host, uint16_t port) {
    sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_ == INVALID_SOCKET) return false;

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        addrinfo hints = {}, *result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
            closesocket(sock_);
            sock_ = INVALID_SOCKET;
            return false;
        }
        addr.sin_addr = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr;
        freeaddrinfo(result);
    }

    if (::connect(sock_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
        return false;
    }

    return do_handshake(host, port);
}

void WsClient::disconnect() {
    if (sock_ != INVALID_SOCKET) {
        send_frame(0x08, nullptr, 0);
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
}

bool WsClient::do_handshake(const std::string& host, uint16_t port) {
    uint8_t key_bytes[16];
    for (int i = 0; i < 16; i++) key_bytes[i] = rand() & 0xFF;

    const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string ws_key;
    for (int i = 0; i < 16; i += 3) {
        uint32_t n = (key_bytes[i] << 16);
        if (i+1 < 16) n |= (key_bytes[i+1] << 8);
        if (i+2 < 16) n |= key_bytes[i+2];
        ws_key += b64[(n>>18)&0x3F];
        ws_key += b64[(n>>12)&0x3F];
        ws_key += (i+1 < 16) ? b64[(n>>6)&0x3F] : '=';
        ws_key += (i+2 < 16) ? b64[n&0x3F] : '=';
    }

    char request[512];
    snprintf(request, sizeof(request),
        "GET / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        host.c_str(), port, ws_key.c_str());

    if (send(sock_, request, static_cast<int>(strlen(request)), 0) <= 0)
        return false;

    char response[4096];
    int n = recv(sock_, response, sizeof(response) - 1, 0);
    if (n <= 0) return false;
    response[n] = '\0';

    return strstr(response, "101") != nullptr;
}

bool WsClient::recv_exact(void* buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(sock_, static_cast<char*>(buf) + total, len - total, 0);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

bool WsClient::send_frame(uint8_t opcode, const void* data, size_t len) {
    std::vector<uint8_t> frame;

    frame.push_back(0x80 | opcode);

    if (len < 126) {
        frame.push_back(0x80 | static_cast<uint8_t>(len));
    } else if (len < 65536) {
        frame.push_back(0x80 | 126);
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        frame.push_back(0x80 | 127);
        for (int i = 7; i >= 0; i--)
            frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
    }

    uint8_t mask[4];
    for (int i = 0; i < 4; i++) mask[i] = rand() & 0xFF;
    frame.insert(frame.end(), mask, mask + 4);

    size_t offset = frame.size();
    frame.resize(offset + len);
    auto* src = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; i++)
        frame[offset + i] = (src ? src[i] : 0) ^ mask[i % 4];

    int total = 0;
    int to_send = static_cast<int>(frame.size());
    while (total < to_send) {
        int sent = send(sock_, reinterpret_cast<const char*>(frame.data()) + total, to_send - total, 0);
        if (sent <= 0) return false;
        total += sent;
    }
    return true;
}

bool WsClient::recv_frame(std::vector<uint8_t>& payload, uint8_t& opcode) {
    uint8_t header[2];
    if (!recv_exact(header, 2)) return false;

    opcode = header[0] & 0x0F;
    bool masked = (header[1] & 0x80) != 0;
    uint64_t payload_len = header[1] & 0x7F;

    if (payload_len == 126) {
        uint8_t ext[2];
        if (!recv_exact(ext, 2)) return false;
        payload_len = (ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        uint8_t ext[8];
        if (!recv_exact(ext, 8)) return false;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | ext[i];
    }

    uint8_t mask_key[4] = {};
    if (masked) {
        if (!recv_exact(mask_key, 4)) return false;
    }

    payload.resize(static_cast<size_t>(payload_len));
    if (payload_len > 0) {
        if (!recv_exact(payload.data(), static_cast<int>(payload_len))) return false;
    }

    if (masked) {
        for (size_t i = 0; i < payload.size(); i++)
            payload[i] ^= mask_key[i % 4];
    }

    return true;
}

bool WsClient::send_binary(const void* data, size_t len) {
    return send_frame(0x02, data, len);
}

bool WsClient::send_binary(const std::vector<uint8_t>& data) {
    return send_binary(data.data(), data.size());
}

bool WsClient::recv_binary(std::vector<uint8_t>& data) {
    uint8_t opcode;
    while (true) {
        if (!recv_frame(data, opcode)) return false;
        if (opcode == 0x08) return false;
        if (opcode == 0x09) {
            send_frame(0x0A, data.data(), data.size());
            continue;
        }
        if (opcode == 0x02) return true;
    }
}

} // namespace sakura
