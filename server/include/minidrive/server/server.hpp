#pragma once

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/signal_set.hpp>
#include <memory>
#include <thread>
#include <vector>

#include "minidrive/server/config.hpp"
#include "minidrive/server/filesystem.hpp"
#include "minidrive/server/session_manager.hpp"
#include "minidrive/server/transfer_registry.hpp"
#include "minidrive/server/user_store.hpp"

namespace minidrive::server
{

    class Session;

    class Server
    {
    public:
        explicit Server(ServerConfig config);

        void run();

    private:
        void accept_next();
        void on_accept(std::error_code ec, asio::ip::tcp::socket socket);
        void handle_signal();

        ServerConfig config_;
        asio::io_context io_context_;
        asio::ip::tcp::acceptor acceptor_;
        asio::signal_set signals_;

        Filesystem filesystem_;
        SessionManager session_manager_;
        UserStore user_store_;
        TransferRegistry transfer_registry_;

        std::vector<std::thread> workers_;
    };

} // namespace minidrive::server
