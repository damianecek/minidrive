#pragma once

#include <asio/ip/tcp.hpp>
#include <array>
#include <chrono>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "minidrive/error_codes.hpp"
#include "minidrive/protocol.hpp"
#include "minidrive/server/filesystem.hpp"
#include "minidrive/server/session_manager.hpp"
#include "minidrive/server/transfer_registry.hpp"
#include "minidrive/server/user_store.hpp"

namespace minidrive::server
{

    class Server;

    struct ServerServices
    {
        Filesystem &filesystem;
        SessionManager &session_manager;
        UserStore &user_store;
        TransferRegistry &transfer_registry;
        std::chrono::seconds upload_timeout;
    };

    class Session : public std::enable_shared_from_this<Session>
    {
    public:
        Session(asio::ip::tcp::socket socket, ServerServices services);
        ~Session();

        void start();

        void stop();

    private:
        void read_frame_header();
        void read_frame_payload(std::size_t size);
        void process_message(const nlohmann::json &json);
        void send_response(const minidrive::protocol::ResponseEnvelope &envelope);
        void send_error(minidrive::ErrorCode code, std::string message,
                        std::optional<std::string> request_id = std::nullopt);
        void handle_authenticate(const minidrive::protocol::RequestEnvelope &envelope);
        void on_disconnect();

        // Command handlers
        void handle_list(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_stat(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_mkdir(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_rmdir(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_move(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_copy(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_delete(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_upload_init(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_upload_chunk(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_upload_commit(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_download_init(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_download_chunk(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_sync_enumerate(const minidrive::protocol::RequestEnvelope &envelope);
        void handle_sync_apply(const minidrive::protocol::RequestEnvelope &envelope);

        std::string remote_endpoint() const;

        asio::ip::tcp::socket socket_;
        ServerServices services_;

        std::array<std::uint8_t, 4> header_buffer_{};
        std::vector<std::uint8_t> buffer_;
        bool authenticated_{false};
        SessionPaths session_paths_{};
        struct DownloadTransfer
        {
            std::filesystem::path path;
            std::uint64_t total_size{};
            std::uint64_t chunk_size{};
            std::string root_hash;
        };
        std::unordered_map<std::string, DownloadTransfer> downloads_;
    };

} // namespace minidrive::server
