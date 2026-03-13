#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>
#include <string>
#include <vector>
#include <functional>

#pragma comment(lib, "ws2_32.lib")

namespace sakura {

class WsServer {
public:
    using MessageHandler = std::function<void(SOCKET client, const std::vector<uint8_t>& data)>;
    using ConnectHandler = std::function<void(SOCKET client)>;

    WsServer();
    ~WsServer();

    bool start(uint16_t port);
    void stop();
    void set_on_message(MessageHandler handler) { on_message_ = handler; }
    void set_on_connect(ConnectHandler handler) { on_connect_ = handler; }

    bool send_binary(SOCKET client, const void* data, size_t len);
    bool send_binary(SOCKET client, const std::vector<uint8_t>& data);

private:
    void accept_loop();
    void client_loop(SOCKET client);
    bool do_handshake(SOCKET client);
    bool recv_frame(SOCKET client, std::vector<uint8_t>& payload, uint8_t& opcode);
    bool send_frame(SOCKET client, uint8_t opcode, const void* data, size_t len);
    bool recv_exact(SOCKET sock, void* buf, int len);

    SOCKET listen_sock_ = INVALID_SOCKET;
    bool   running_     = false;
    MessageHandler on_message_;
    ConnectHandler on_connect_;
};

} // namespace sakura
