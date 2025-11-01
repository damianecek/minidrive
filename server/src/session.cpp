#include "minidrive/server/session.hpp"

#include <asio/read.hpp>
#include <asio/write.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <unordered_set>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <span>
#include <string>

#include "minidrive/crypto.hpp"
#include "minidrive/error_codes.hpp"
#include "minidrive/framing.hpp"

#include <spdlog/spdlog.h>

namespace minidrive::server
{

    namespace
    {

        std::uint32_t read_u32_be(const std::array<std::uint8_t, 4> &buffer)
        {
            return (static_cast<std::uint32_t>(buffer[0]) << 24) | (static_cast<std::uint32_t>(buffer[1]) << 16) |
                   (static_cast<std::uint32_t>(buffer[2]) << 8) | static_cast<std::uint32_t>(buffer[3]);
        }

        std::vector<std::byte> decode_base64(const std::string &input)
        {
            static const auto table = []
            {
                std::array<int8_t, 256> t{};
                t.fill(-1);
                const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                for (std::size_t i = 0; i < alphabet.size(); ++i)
                {
                    t[static_cast<unsigned char>(alphabet[i])] = static_cast<int8_t>(i);
                }
                t[static_cast<unsigned char>('=')] = -2;
                return t;
            }();

            std::vector<std::byte> output;
            output.reserve((input.size() * 3) / 4);

            std::uint32_t accumulator = 0;
            int bits_collected = 0;
            for (const char ch : input)
            {
                const unsigned char c = static_cast<unsigned char>(ch);
                const int value = table[c];
                if (value == -1)
                {
                    if (!std::isspace(static_cast<unsigned char>(c)))
                    {
                        return {};
                    }
                    continue;
                }
                if (value == -2)
                {
                    break;
                }
                accumulator = (accumulator << 6) | static_cast<std::uint32_t>(value);
                bits_collected += 6;
                if (bits_collected >= 8)
                {
                    bits_collected -= 8;
                    const auto byte_value = static_cast<std::uint8_t>((accumulator >> bits_collected) & 0xFFu);
                    output.push_back(static_cast<std::byte>(byte_value));
                }
            }

            return output;
        }

        std::string encode_base64(std::span<const std::byte> data)
        {
            static constexpr char kAlphabet[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            std::string output;
            output.reserve(((data.size() + 2) / 3) * 4);

            std::uint32_t buffer = 0;
            int bits_collected = 0;

            for (const auto byte : data)
            {
                buffer = (buffer << 8u) | static_cast<std::uint32_t>(byte);
                bits_collected += 8;
                while (bits_collected >= 6)
                {
                    bits_collected -= 6;
                    const auto index = static_cast<std::size_t>((buffer >> bits_collected) & 0x3Fu);
                    output.push_back(kAlphabet[index]);
                }
            }

            if (bits_collected > 0)
            {
                buffer <<= (6 - bits_collected);
                const auto index = static_cast<std::size_t>(buffer & 0x3F);
                output.push_back(kAlphabet[index]);
            }

            while (output.size() % 4 != 0)
            {
                output.push_back('=');
            }

            return output;
        }

        std::uint64_t to_unix_time(const std::filesystem::file_time_type &time)
        {
            using namespace std::chrono;
            const auto system_time = time_point_cast<seconds>(time - std::filesystem::file_time_type::clock::now() +
                                                              std::chrono::system_clock::now());
            return static_cast<std::uint64_t>(system_time.time_since_epoch().count());
        }

        std::string relative_path_or_dot(const std::filesystem::path &base, const std::filesystem::path &target)
        {
            auto rel = target.lexically_relative(base);
            auto str = rel.generic_string();
            if (str.empty() || str == ".")
            {
                return ".";
            }
            return str;
        }

        minidrive::protocol::ResponseEnvelope make_ok_response(nlohmann::json payload,
                                                               const std::optional<std::string> &request_id)
        {
            minidrive::protocol::ResponseEnvelope envelope;
            envelope.kind = minidrive::protocol::ResponseKind::Ok;
            envelope.payload = std::move(payload);
            envelope.message = "";
            envelope.error = minidrive::ErrorCode::Ok;
            envelope.request_id = request_id;
            return envelope;
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

    void Session::handle_authenticate(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (authenticated_)
        {
            send_error(minidrive::ErrorCode::Conflict, "Already authenticated", envelope.request_id);
            return;
        }

        minidrive::protocol::AuthenticateRequest request;
        try
        {
            request = envelope.payload.get<minidrive::protocol::AuthenticateRequest>();
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InvalidPayload, ex.what(), envelope.request_id);
            return;
        }

        std::string identity = request.public_mode ? std::string{"public"} : request.username;
        if (identity.empty())
        {
            send_error(minidrive::ErrorCode::InvalidPayload, "Username is required", envelope.request_id);
            return;
        }

        if (!request.public_mode)
        {
            if (request.register_user)
            {
                std::string message;
                if (!services_.user_store.register_user(request.username, request.password, message))
                {
                    send_error(minidrive::ErrorCode::Conflict, message, envelope.request_id);
                    return;
                }
            }
            if (!services_.user_store.authenticate(request.username, request.password))
            {
                send_error(minidrive::ErrorCode::AuthenticationFailed, "Invalid credentials", envelope.request_id);
                return;
            }
        }

        session_paths_ = services_.filesystem.prepare_session_paths(identity, request.public_mode);

        if (!services_.session_manager.try_register(identity, shared_from_this()))
        {
            send_error(minidrive::ErrorCode::Busy, "Session already active", envelope.request_id);
            return;
        }

        authenticated_ = true;
        minidrive::protocol::AuthenticateResponse response{
            .success = true,
            .newly_registered = request.register_user && !request.public_mode,
            .identity = identity,
        };
        nlohmann::json payload = response;
        send_response(make_ok_response(std::move(payload), envelope.request_id));
        spdlog::info("Session authenticated as {} ({})", session_paths_.identity, remote_endpoint());
    }

    void Session::handle_list(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::ListRequest>();
            const auto entries = services_.filesystem.list_directory(session_paths_, request.path);
            nlohmann::json payload; // default object
            payload["entries"] = entries;
            send_response(make_ok_response(payload, envelope.request_id));
        }
        catch (const FilesystemError &fs)
        {
            send_error(fs.code(), fs.what(), envelope.request_id);
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_stat(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::PathRequest>();
            const auto info = services_.filesystem.stat_path(session_paths_, request.path);
            nlohmann::json payload;
            payload["metadata"] = info;
            send_response(make_ok_response(payload, envelope.request_id));
        }
        catch (const FilesystemError &fs)
        {
            send_error(fs.code(), fs.what(), envelope.request_id);
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_mkdir(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::PathRequest>();
            services_.filesystem.create_directory(session_paths_, request.path);
            send_response(make_ok_response(nlohmann::json::object(), envelope.request_id));
        }
        catch (const FilesystemError &fs)
        {
            send_error(fs.code(), fs.what(), envelope.request_id);
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_rmdir(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::PathRequest>();
            services_.filesystem.remove_directory(session_paths_, request.path);
            send_response(make_ok_response(nlohmann::json::object(), envelope.request_id));
        }
        catch (const FilesystemError &fs)
        {
            send_error(fs.code(), fs.what(), envelope.request_id);
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_move(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::MoveCopyRequest>();
            services_.filesystem.move_path(session_paths_, request.source, request.destination);
            send_response(make_ok_response(nlohmann::json::object(), envelope.request_id));
        }
        catch (const FilesystemError &fs)
        {
            send_error(fs.code(), fs.what(), envelope.request_id);
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_copy(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::MoveCopyRequest>();
            services_.filesystem.copy_path(session_paths_, request.source, request.destination);
            send_response(make_ok_response(nlohmann::json::object(), envelope.request_id));
        }
        catch (const FilesystemError &fs)
        {
            send_error(fs.code(), fs.what(), envelope.request_id);
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_delete(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::PathRequest>();
            services_.filesystem.remove_file(session_paths_, request.path);
            send_response(make_ok_response(nlohmann::json::object(), envelope.request_id));
        }
        catch (const FilesystemError &fs)
        {
            send_error(fs.code(), fs.what(), envelope.request_id);
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_upload_init(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            services_.transfer_registry.cleanup_expired(services_.upload_timeout);
            const auto request = envelope.payload.get<minidrive::protocol::UploadInitRequest>();
            const auto target = services_.filesystem.resolve_for_new_entry(session_paths_, request.remote_path);
            auto info = services_.transfer_registry.create_or_resume(session_paths_.identity, target, request.file_size,
                                                                     request.chunk_size, request.root_hash, request.resume);

            minidrive::protocol::TransferDescriptor descriptor{
                .transfer_id = info.state.transfer_id,
                .total_size = info.state.file_size,
                .chunk_size = info.state.chunk_size,
                .root_hash = info.state.root_hash,
            };

            nlohmann::json payload;
            payload["descriptor"] = descriptor;
            payload["bytes_written"] = info.state.bytes_written;
            payload["resumed"] = info.resumed;
            send_response(make_ok_response(payload, envelope.request_id));
        }
        catch (const FilesystemError &fs)
        {
            send_error(fs.code(), fs.what(), envelope.request_id);
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_upload_chunk(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::UploadChunkRequest>();
            const auto data = decode_base64(request.data_base64);
            if (data.empty() && !request.data_base64.empty())
            {
                send_error(minidrive::ErrorCode::InvalidPayload, "Invalid chunk data", envelope.request_id);
                return;
            }
            std::string error_message;
            if (!services_.transfer_registry.append_chunk(request.transfer_id, request.offset, data, request.chunk_hash,
                                                          error_message))
            {
                send_error(minidrive::ErrorCode::InvalidPayload, error_message, envelope.request_id);
                return;
            }
            nlohmann::json payload;
            payload["bytes"] = data.size();
            send_response(make_ok_response(payload, envelope.request_id));
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_upload_commit(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::UploadCommitRequest>();
            std::string error_message;
            if (!services_.transfer_registry.commit(request.transfer_id, request.final_hash, error_message))
            {
                send_error(minidrive::ErrorCode::InvalidPayload, error_message, envelope.request_id);
                return;
            }
            send_response(make_ok_response(nlohmann::json::object(), envelope.request_id));
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_download_init(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::DownloadInitRequest>();
            const auto path = services_.filesystem.resolve(session_paths_, request.remote_path);
            if (std::filesystem::is_directory(path))
            {
                send_error(minidrive::ErrorCode::Unsupported, "Cannot download a directory", envelope.request_id);
                return;
            }
            const auto file_size = std::filesystem::file_size(path);
            constexpr std::uint64_t kDefaultChunk = 1 << 20; // 1 MiB
            const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            const auto file_hash = crypto::hash_file(path);
            auto descriptor = minidrive::protocol::TransferDescriptor{
                .transfer_id = "download-" + std::to_string(now),
                .total_size = file_size,
                .chunk_size = kDefaultChunk,
                .root_hash = file_hash,
            };
            downloads_[descriptor.transfer_id] = DownloadTransfer{
                .path = path,
                .total_size = file_size,
                .chunk_size = descriptor.chunk_size,
                .root_hash = file_hash,
            };
            auto metadata = services_.filesystem.stat_path(session_paths_, request.remote_path);
            metadata.content_hash = file_hash;
            minidrive::protocol::DownloadInitResponse response{
                .descriptor = descriptor,
                .metadata = metadata,
            };
            nlohmann::json payload = response;
            send_response(make_ok_response(std::move(payload), envelope.request_id));
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_download_chunk(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::DownloadChunkRequest>();
            auto it = downloads_.find(request.transfer_id);
            if (it == downloads_.end())
            {
                send_error(minidrive::ErrorCode::InvalidPayload, "Unknown download transfer", envelope.request_id);
                return;
            }
            const auto &transfer = it->second;
            if (request.offset > transfer.total_size)
            {
                send_error(minidrive::ErrorCode::InvalidPayload, "Offset beyond end of file", envelope.request_id);
                return;
            }

            const auto remaining = transfer.total_size - request.offset;
            if (remaining == 0)
            {
                nlohmann::json payload = minidrive::protocol::DownloadChunkResponse{
                    .transfer_id = request.transfer_id,
                    .offset = request.offset,
                    .bytes = 0,
                    .done = true,
                    .data_base64 = std::string{},
                    .chunk_hash = std::string{},
                };
                downloads_.erase(it);
                send_response(make_ok_response(payload, envelope.request_id));
                return;
            }

            const std::uint64_t requested = request.max_bytes == 0 ? transfer.chunk_size : request.max_bytes;
            const auto chunk_size = static_cast<std::size_t>(std::min<std::uint64_t>(
                transfer.chunk_size, std::min<std::uint64_t>(requested, remaining)));
            std::ifstream file(transfer.path, std::ios::binary);
            if (!file.is_open())
            {
                send_error(minidrive::ErrorCode::InternalError, "Failed to open file for download", envelope.request_id);
                return;
            }
            file.seekg(static_cast<std::streamoff>(request.offset));
            std::vector<char> buffer(chunk_size);
            file.read(buffer.data(), static_cast<std::streamsize>(chunk_size));
            const auto read_count = static_cast<std::size_t>(file.gcount());
            if (read_count == 0)
            {
                send_error(minidrive::ErrorCode::InternalError, "Failed to read file chunk", envelope.request_id);
                return;
            }
            std::vector<std::byte> bytes(read_count);
            std::memcpy(bytes.data(), buffer.data(), read_count);
            const auto chunk_hash = crypto::hash_bytes(bytes);
            const auto encoded = encode_base64(bytes);
            const bool done = request.offset + read_count >= transfer.total_size;
            if (done)
            {
                downloads_.erase(it);
            }
            nlohmann::json payload = minidrive::protocol::DownloadChunkResponse{
                .transfer_id = request.transfer_id,
                .offset = request.offset,
                .bytes = static_cast<std::uint64_t>(read_count),
                .done = done,
                .data_base64 = encoded,
                .chunk_hash = chunk_hash,
            };
            send_response(make_ok_response(payload, envelope.request_id));
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_sync_enumerate(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::PathRequest>();
            const auto base = services_.filesystem.resolve(session_paths_, request.path);
            if (!std::filesystem::exists(base))
            {
                send_error(minidrive::ErrorCode::NotFound, "Path does not exist", envelope.request_id);
                return;
            }
            if (!std::filesystem::is_directory(base))
            {
                send_error(minidrive::ErrorCode::InvalidPayload, "Target is not a directory", envelope.request_id);
                return;
            }

            std::vector<minidrive::protocol::FileMetadata> entries;
            std::error_code ec;
            auto root_time = std::filesystem::last_write_time(base, ec);
            if (ec)
            {
                root_time = std::filesystem::file_time_type::clock::now();
            }
            minidrive::protocol::FileMetadata root_meta{
                .path = ".",
                .size = 0,
                .modified_time = to_unix_time(root_time),
                .is_directory = true,
                .content_hash = std::nullopt,
            };
            entries.push_back(root_meta);

            for (std::filesystem::recursive_directory_iterator it(base); it != std::filesystem::recursive_directory_iterator(); ++it)
            {
                ec.clear();
                const auto rel_path = relative_path_or_dot(base, it->path());
                minidrive::protocol::FileMetadata metadata{};
                metadata.path = rel_path;
                metadata.is_directory = it->is_directory(ec);
                if (ec)
                {
                    metadata.is_directory = false;
                }
                std::uint64_t size = 0;
                if (!metadata.is_directory)
                {
                    auto file_size = it->file_size(ec);
                    if (!ec)
                    {
                        size = static_cast<std::uint64_t>(file_size);
                    }
                }
                metadata.size = size;
                auto modified = std::filesystem::last_write_time(it->path(), ec);
                if (ec)
                {
                    modified = std::filesystem::file_time_type::clock::now();
                }
                metadata.modified_time = to_unix_time(modified);
                if (!metadata.is_directory)
                {
                    try
                    {
                        metadata.content_hash = minidrive::crypto::hash_file(it->path());
                    }
                    catch (const std::exception &)
                    {
                        metadata.content_hash.reset();
                    }
                }
                entries.push_back(std::move(metadata));
            }

            nlohmann::json payload;
            payload["entries"] = entries;
            send_response(make_ok_response(std::move(payload), envelope.request_id));
        }
        catch (const std::exception &ex)
        {
            spdlog::error("SYNC_ENUMERATE failed for {}: {}", session_paths_.identity, ex.what());
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_sync_apply(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto plan = envelope.payload.get<minidrive::protocol::SyncPlan>();
            for (const auto &entry : plan.entries)
            {
                if (entry.action == minidrive::protocol::SyncAction::DeleteRemote)
                {
                    try
                    {
                        const auto target = services_.filesystem.resolve(session_paths_, entry.metadata.path);
                        if (entry.metadata.is_directory)
                        {
                            std::filesystem::remove_all(target);
                        }
                        else
                        {
                            std::filesystem::remove(target);
                        }
                    }
                    catch (const std::exception &)
                    {
                        // Ignore missing targets during delete operations
                    }
                }
            }
            send_response(make_ok_response(nlohmann::json::object(), envelope.request_id));
        }
        catch (const std::exception &ex)
        {
            spdlog::error("SYNC_APPLY failed for {}: {}", session_paths_.identity, ex.what());
            send_error(minidrive::ErrorCode::InvalidPayload, ex.what(), envelope.request_id);
        }
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
