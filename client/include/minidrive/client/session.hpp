#pragma once

#include <asio.hpp>

#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "minidrive/client/config.hpp"
#include "minidrive/client/logger.hpp"
#include "minidrive/client/transfer_state_store.hpp"
#include "minidrive/protocol.hpp"

namespace minidrive::client
{

    class ClientSession
    {
    public:
        ClientSession(ClientConfig config, Logger logger);

        int run();

    private:
        struct SnapshotEntry
        {
            bool is_directory{};
            std::uint64_t size{};
            std::string hash;
        };

        void connect();
        static std::string prompt_password(const std::string &username);
        bool ask_yes_no(const std::string &question) const;
        void authenticate();
        void interactive_shell();
        void resume_pending_transfers();
        bool dispatch(const std::string &command, const std::vector<std::string> &args);
        void discard_pending_transfers(const std::vector<TransferStateStore::Entry> &entries);
        void remove_partial_download_artifacts(const TransferStateStore::Entry &entry);

        bool handle_list(const std::vector<std::string> &args);
        bool handle_stat(const std::vector<std::string> &args);
        bool handle_cd(const std::vector<std::string> &args);
        bool handle_simple_path_command(minidrive::protocol::Command command, const std::vector<std::string> &args,
                                        std::size_t expected_args);
        bool handle_move_copy(minidrive::protocol::Command command, const std::vector<std::string> &args);
        bool handle_upload(const std::vector<std::string> &args);
        bool handle_download(const std::vector<std::string> &args);
        bool perform_upload(const std::filesystem::path &local_path, const std::string &remote_target, bool from_resume);
        bool perform_download(const std::string &remote_path, const std::filesystem::path &local_target, bool resume);
        bool handle_sync(const std::vector<std::string> &args);

        std::map<std::string, SnapshotEntry> build_local_snapshot(const std::filesystem::path &root);
        std::map<std::string, SnapshotEntry> build_remote_snapshot(const std::string &remote_root);

        bool ensure_remote_directory(const std::string &remote_path);
        bool ensure_remote_parent_directory(const std::string &remote_path);
        std::string join_remote_path(const std::string &remote_root, const std::string &relative) const;
        std::string normalize_remote_for_join(std::string path) const;

        minidrive::protocol::ResponseEnvelope rpc(minidrive::protocol::Command command,
                                                  const nlohmann::json &payload = nlohmann::json::object());
        void print_help() const;
        void print_error(const minidrive::protocol::ResponseEnvelope &response) const;
        std::string resolve_remote_path(const std::string &input) const;
        static std::string normalize_remote(std::string path);
        std::string identity_prompt() const;
        std::string next_request_id();

        ClientConfig config_;
        Logger logger_;
        TransferStateStore state_store_;
        asio::io_context io_context_;
        asio::ip::tcp::socket socket_;
        std::string identity_;
        std::string remote_cwd_{"."};
        std::uint64_t request_counter_{0};
    };

} // namespace minidrive::client
