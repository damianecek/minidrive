#include "minidrive/server/server.hpp"

#include <asio/ip/address.hpp>
#include <asio/post.hpp>

#include <csignal>
#include <iostream>
#include <thread>

#include <spdlog/spdlog.h>

#include "minidrive/server/session.hpp"

namespace minidrive::server
{

    namespace
    {

        std::size_t resolve_worker_threads(std::size_t requested)
        {
            if (requested > 0)
            {
                return requested;
            }
            const auto hardware = std::thread::hardware_concurrency();
            return hardware == 0 ? 2 : hardware;
        }

    } // namespace

    Server::Server(ServerConfig config)
        : config_(std::move(config)),
          io_context_(static_cast<int>(resolve_worker_threads(config_.worker_threads))),
          acceptor_(io_context_),
          signals_(io_context_),
          filesystem_(config_.root),
          user_store_(config_.root),
          transfer_registry_(config_.root)
    {
        const auto address = asio::ip::make_address(config_.address);
        const asio::ip::tcp::endpoint endpoint(address, config_.port);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();

        spdlog::info("Listening on {}:{} with root {}", config_.address, config_.port, config_.root.string());

        signals_.add(SIGINT);
        signals_.add(SIGTERM);
        signals_.async_wait([this](const std::error_code &ec, int /*signal*/)
                            {
        if (!ec) {
            handle_signal();
        } });
    }

    void Server::run()
    {
        accept_next();

        const auto worker_count = resolve_worker_threads(config_.worker_threads);
        workers_.reserve(worker_count > 0 ? worker_count - 1 : 0);
        for (std::size_t i = 1; i < worker_count; ++i)
        {
            workers_.emplace_back([this]
                                  { io_context_.run(); });
        }
        spdlog::info("Server event loop running with {} threads", worker_count);
        io_context_.run();

        for (auto &worker : workers_)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }
    }

    void Server::accept_next()
    {
        acceptor_.async_accept([this](const std::error_code &ec, asio::ip::tcp::socket socket)
                               { on_accept(ec, std::move(socket)); });
    }

    void Server::on_accept(std::error_code ec, asio::ip::tcp::socket socket)
    {
        if (!ec)
        {
            ServerServices services{filesystem_, session_manager_, user_store_, transfer_registry_, config_.upload_timeout};
            auto session = std::make_shared<Session>(std::move(socket), services);
            session->start();
            spdlog::debug("Accepted new connection");
        }
        if (!ec || ec == asio::error::operation_aborted)
        {
            if (acceptor_.is_open())
            {
                accept_next();
            }
        }
        else
        {
            spdlog::error("Accept error: {}", ec.message());
            accept_next();
        }
    }

    void Server::handle_signal()
    {
        std::error_code ec;
        acceptor_.close(ec);
        io_context_.stop();
        spdlog::info("Signal received, shutting down");
    }

} // namespace minidrive::server
