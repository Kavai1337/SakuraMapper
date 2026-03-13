#include "ws_server.h"
#include <thread>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <algorithm>

namespace {

struct SHA1 {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buffer[64];

    SHA1() {
        state[0] = 0x67452301; state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE; state[3] = 0x10325476;
        state[4] = 0xC3D2E1F0; count = 0;
    }

    static uint32_t rol(uint32_t v, int bits) { return (v << bits) | (v >> (32 - bits)); }

    void transform(const uint8_t block[64]) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = (block[i*4]<<24)|(block[i*4+1]<<16)|(block[i*4+2]<<8)|block[i*4+3];
        for (int i = 16; i < 80; i++)
            w[i] = rol(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);

        uint32_t a=state[0], b=state[1], c=state[2], d=state[3], e=state[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if      (i < 20) { f=(b&c)|((~b)&d); k=0x5A827999; }
            else if (i < 40) { f=b^c^d;           k=0x6ED9EBA1; }
            else if (i < 60) { f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
            else              { f=b^c^d;           k=0xCA62C1D6; }
            uint32_t t = rol(a,5)+f+e+k+w[i];
            e=d; d=c; c=rol(b,30); b=a; a=t;
        }
        state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e;
    }

    void update(const uint8_t* data, size_t len) {
        size_t idx = static_cast<size_t>(count % 64);
        count += len;
        for (size_t i = 0; i < len; i++) {
            buffer[idx++] = data[i];
            if (idx == 64) { transform(buffer); idx = 0; }
        }
    }

    void final(uint8_t digest[20]) {
        uint64_t bits = count * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        pad = 0;
        while (count % 64 != 56) update(&pad, 1);
        uint8_t bits_be[8];
        for (int i = 7; i >= 0; i--) { bits_be[i] = bits & 0xFF; bits >>= 8; }
        update(bits_be, 8);
        for (int i = 0; i < 5; i++) {
            digest[i*4]   = (state[i]>>24)&0xFF;
            digest[i*4+1] = (state[i]>>16)&0xFF;
            digest[i*4+2] = (state[i]>>8)&0xFF;
            digest[i*4+3] = state[i]&0xFF;
        }
    }
};

const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const uint8_t* data, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = (data[i] << 16);
        if (i+1 < len) n |= (data[i+1] << 8);
        if (i+2 < len) n |= data[i+2];
        out += b64[(n>>18)&0x3F];
        out += b64[(n>>12)&0x3F];
        out += (i+1 < len) ? b64[(n>>6)&0x3F] : '=';
        out += (i+2 < len) ? b64[n&0x3F] : '=';
    }
    return out;
}

}

namespace sakura {

WsServer::WsServer() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
}

WsServer::~WsServer() {
    stop();
    WSACleanup();
}

bool WsServer::start(uint16_t port) {
    listen_sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock_ == INVALID_SOCKET) return false;

    int opt = 1;
    setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(listen_sock_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listen_sock_);
        return false;
    }

    if (listen(listen_sock_, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listen_sock_);
        return false;
    }

    running_ = true;
    std::thread(&WsServer::accept_loop, this).detach();
    return true;
}

void WsServer::stop() {
    running_ = false;
    if (listen_sock_ != INVALID_SOCKET) {
        closesocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET;
    }
}

void WsServer::accept_loop() {
    while (running_) {
        sockaddr_in client_addr = {};
        int addr_len = sizeof(client_addr);
        SOCKET client = accept(listen_sock_, (sockaddr*)&client_addr, &addr_len);
        if (client == INVALID_SOCKET) continue;

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        printf("[Server] Client connected from %s\n", ip);

        std::thread(&WsServer::client_loop, this, client).detach();
    }
}

void WsServer::client_loop(SOCKET client) {
    if (!do_handshake(client)) {
        printf("[Server] WebSocket handshake failed\n");
        closesocket(client);
        return;
    }

    printf("[Server] WebSocket handshake complete\n");

    if (on_connect_) on_connect_(client);

    while (running_) {
        std::vector<uint8_t> payload;
        uint8_t opcode;
        if (!recv_frame(client, payload, opcode)) break;

        if (opcode == 0x08) break;
        if (opcode == 0x09) {
            send_frame(client, 0x0A, payload.data(), payload.size());
            continue;
        }

        if (opcode == 0x02 && on_message_) {
            on_message_(client, payload);
        }
    }

    printf("[Server] Client disconnected\n");
    closesocket(client);
}

bool WsServer::do_handshake(SOCKET client) {
    char buf[4096];
    int received = recv(client, buf, sizeof(buf) - 1, 0);
    if (received <= 0) return false;
    buf[received] = '\0';

    std::string request(buf);
    std::string key_header = "Sec-WebSocket-Key: ";
    auto pos = request.find(key_header);
    if (pos == std::string::npos) return false;

    auto end = request.find("\r\n", pos);
    std::string ws_key = request.substr(pos + key_header.size(), end - pos - key_header.size());

    std::string magic = ws_key + "258EAFA5-E914-47DA-95CA-5AB5DC11E65A";
    SHA1 sha;
    sha.update(reinterpret_cast<const uint8_t*>(magic.c_str()), magic.size());
    uint8_t digest[20];
    sha.final(digest);
    std::string accept_key = base64_encode(digest, 20);

    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept_key + "\r\n\r\n";

    send(client, response.c_str(), static_cast<int>(response.size()), 0);
    return true;
}

bool WsServer::recv_exact(SOCKET sock, void* buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(sock, static_cast<char*>(buf) + total, len - total, 0);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

bool WsServer::recv_frame(SOCKET client, std::vector<uint8_t>& payload, uint8_t& opcode) {
    uint8_t header[2];
    if (!recv_exact(client, header, 2)) return false;

    opcode = header[0] & 0x0F;
    bool masked = (header[1] & 0x80) != 0;
    uint64_t payload_len = header[1] & 0x7F;

    if (payload_len == 126) {
        uint8_t ext[2];
        if (!recv_exact(client, ext, 2)) return false;
        payload_len = (ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        uint8_t ext[8];
        if (!recv_exact(client, ext, 8)) return false;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | ext[i];
    }

    uint8_t mask_key[4] = {};
    if (masked) {
        if (!recv_exact(client, mask_key, 4)) return false;
    }

    payload.resize(static_cast<size_t>(payload_len));
    if (payload_len > 0) {
        if (!recv_exact(client, payload.data(), static_cast<int>(payload_len))) return false;
    }

    if (masked) {
        for (size_t i = 0; i < payload.size(); i++)
            payload[i] ^= mask_key[i % 4];
    }

    return true;
}

bool WsServer::send_frame(SOCKET client, uint8_t opcode, const void* data, size_t len) {
    std::vector<uint8_t> frame;

    frame.push_back(0x80 | opcode);

    if (len < 126) {
        frame.push_back(static_cast<uint8_t>(len));
    } else if (len < 65536) {
        frame.push_back(126);
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; i--)
            frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
    }

    size_t header_size = frame.size();
    frame.resize(header_size + len);
    if (data && len > 0)
        memcpy(frame.data() + header_size, data, len);

    int total = 0;
    int to_send = static_cast<int>(frame.size());
    while (total < to_send) {
        int sent = send(client, reinterpret_cast<const char*>(frame.data()) + total, to_send - total, 0);
        if (sent <= 0) return false;
        total += sent;
    }
    return true;
}

bool WsServer::send_binary(SOCKET client, const void* data, size_t len) {
    return send_frame(client, 0x02, data, len);
}

bool WsServer::send_binary(SOCKET client, const std::vector<uint8_t>& data) {
    return send_binary(client, data.data(), data.size());
}

} // namespace sakura
