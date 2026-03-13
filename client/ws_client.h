#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace sakura {

class WsClient {
public:
    WsClient();
    ~WsClient();

    bool connect(const std::string& host, uint16_t port);
    void disconnect();
    bool is_connected() const { return sock_ != INVALID_SOCKET; }

    bool send_binary(const void* data, size_t len);
    bool send_binary(const std::vector<uint8_t>& data);
    bool recv_binary(std::vector<uint8_t>& data);

private:
    bool do_handshake(const std::string& host, uint16_t port);
    bool send_frame(uint8_t opcode, const void* data, size_t len);
    bool recv_frame(std::vector<uint8_t>& payload, uint8_t& opcode);
    bool recv_exact(void* buf, int len);

    SOCKET sock_ = INVALID_SOCKET;
};

} // namespace sakura
