#include "minidrive/server/session.hpp"

#include <asio/read.hpp>
#include <asio/write.hpp>

#include <array>
#include <chrono>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "minidrive/error_codes.hpp"
#include "minidrive/framing.hpp"
#include "minidrive/protocol.hpp"

namespace minidrive::server
{

    namespace
    {

        std::uint32_t read_u32_be(const std::array<std::uint8_t, 4> &buffer)
        {
            return (static_cast<std::uint32_t>(buffer[0]) << 24) | (static_cast<std::uint32_t>(buffer[1]) << 16) |
                   (static_cast<std::uint32_t>(buffer[2]) << 8) | static_cast<std::uint32_t>(buffer[3]);
        }

    } // namespace

    Session::Session(asio::ip::tcp::socket socket, ServerServices services)
        : socket_(std::move(socket)), services_(services) {}

    Session::~Session()
    {
        on_disconnect();
    }

    void Session::start()
    {
        spdlog::info("Client connected from {}", remote_endpoint());
        read_frame_header();
    }

    void Session::stop()
    {
        std::error_code ec;
        spdlog::info("Closing connection for {}", remote_endpoint());
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
        on_disconnect();
    }

    void Session::read_frame_header()
    {
        auto self = shared_from_this();
        asio::async_read(socket_, asio::buffer(header_buffer_),
                         [this, self](const std::error_code &ec, std::size_t /*bytes_transferred*/)
                         {
                             if (ec)
                             {
                                 stop();
                                 return;
                             }
                             const std::uint32_t payload_size = read_u32_be(header_buffer_);
                             if (payload_size == 0)
                             {
                                 read_frame_header();
                                 return;
                             }
                             buffer_.resize(payload_size);
                             read_frame_payload(payload_size);
                         });
    }

    void Session::read_frame_payload(std::size_t size)
    {
        auto self = shared_from_this();
        asio::async_read(socket_, asio::buffer(buffer_.data(), size),
                         [this, self](const std::error_code &ec, std::size_t /*bytes_transferred*/)
                         {
                             if (ec)
                             {
                                 stop();
                                 return;
                             }
                             try
                             {
                                 const std::string payload(reinterpret_cast<const char *>(buffer_.data()), buffer_.size());
                                 const auto json = nlohmann::json::parse(payload);
                                 process_message(json);
                             }
                             catch (const std::exception &ex)
                             {
                                 send_error(minidrive::ErrorCode::InvalidPayload, ex.what());
                             }
                             read_frame_header();
                         });
    }

    void Session::process_message(const nlohmann::json &json)
    {
        minidrive::protocol::RequestEnvelope envelope;
        try
        {
            envelope = json.get<minidrive::protocol::RequestEnvelope>();
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InvalidPayload, ex.what());
            return;
        }

        spdlog::debug("{} -> command {}", remote_endpoint(), minidrive::protocol::to_string(envelope.command));

        switch (envelope.command)
        {
        case minidrive::protocol::Command::Authenticate:
            handle_authenticate(envelope);
            break;
        case minidrive::protocol::Command::List:
            handle_list(envelope);
            break;
        case minidrive::protocol::Command::Stat:
            handle_stat(envelope);
            break;
        case minidrive::protocol::Command::Mkdir:
            handle_mkdir(envelope);
            break;
        case minidrive::protocol::Command::Rmdir:
            handle_rmdir(envelope);
            break;
        case minidrive::protocol::Command::Move:
            handle_move(envelope);
            break;
        case minidrive::protocol::Command::Copy:
            handle_copy(envelope);
            break;
        case minidrive::protocol::Command::Delete:
            handle_delete(envelope);
            break;
        case minidrive::protocol::Command::UploadInit:
            handle_upload_init(envelope);
            break;
        case minidrive::protocol::Command::UploadChunk:
            handle_upload_chunk(envelope);
            break;
        case minidrive::protocol::Command::UploadCommit:
            handle_upload_commit(envelope);
            break;
        case minidrive::protocol::Command::DownloadInit:
            handle_download_init(envelope);
            break;
        case minidrive::protocol::Command::DownloadChunk:
            handle_download_chunk(envelope);
            break;
        case minidrive::protocol::Command::SyncEnumerate:
            handle_sync_enumerate(envelope);
            break;
        case minidrive::protocol::Command::SyncApply:
            handle_sync_apply(envelope);
            break;
        default:
            send_error(minidrive::ErrorCode::Unsupported, "Command not supported", envelope.request_id);
            break;
        }
    }

    void Session::send_response(const minidrive::protocol::ResponseEnvelope &envelope)
    {
        try
        {
            const auto json = nlohmann::json(envelope);
            auto frame = std::make_shared<std::vector<std::uint8_t>>(minidrive::protocol::encode_frame(json));
            auto self = shared_from_this();
            asio::async_write(socket_, asio::buffer(*frame),
                              [this, self, frame](const std::error_code &ec, std::size_t /*bytes_transferred*/)
                              {
                                  if (ec)
                                  {
                                      stop();
                                  }
                              });
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what());
        }
    }

    void Session::send_error(minidrive::ErrorCode code, std::string message, std::optional<std::string> request_id)
    {
        minidrive::protocol::ResponseEnvelope envelope;
        envelope.kind = minidrive::protocol::ResponseKind::Error;
        envelope.error = code;
        envelope.message = std::move(message);
        envelope.request_id = std::move(request_id);
        send_response(envelope);
    }

    void Session::on_disconnect()
    {
        if (authenticated_)
        {
            services_.session_manager.unregister(session_paths_.identity, this);
            authenticated_ = false;
        }
        downloads_.clear();
    }

    std::string Session::remote_endpoint() const
    {
        std::error_code ec;
        const auto endpoint = socket_.remote_endpoint(ec);
        if (ec)
        {
            return "unknown";
        }
        std::string address;
        try
        {
            address = endpoint.address().to_string();
        }
        catch (...)
        {
            return "unknown";
        }
        return address + ":" + std::to_string(endpoint.port());
    }

} // namespace minidrive::server
