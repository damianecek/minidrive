#pragma once

#include <chrono>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <vector>

namespace minidrive::server
{

    struct UploadState
    {
        std::string transfer_id;
        std::string identity;
        std::filesystem::path final_path;
        std::filesystem::path temp_path;
        std::uint64_t file_size{};
        std::uint64_t chunk_size{};
        std::uint64_t bytes_written{};
        std::string root_hash;
        std::chrono::system_clock::time_point last_update{};
    };

    struct ResumeInfo
    {
        UploadState state;
        bool resumed{};
    };

    class TransferRegistry
    {
    public:
        explicit TransferRegistry(std::filesystem::path storage_root);

        ResumeInfo create_or_resume(const std::string &identity, const std::filesystem::path &target_path,
                                    std::uint64_t file_size, std::uint64_t chunk_size, const std::string &root_hash,
                                    bool resume_requested);

        bool append_chunk(const std::string &transfer_id, std::uint64_t offset, const std::vector<std::byte> &data,
                          const std::string &chunk_hash, std::string &error_message);

        bool commit(const std::string &transfer_id, const std::string &final_hash, std::string &error_message);

        std::optional<UploadState> find(const std::string &transfer_id) const;

        void cleanup_expired(std::chrono::seconds max_age);

    private:
        std::filesystem::path registry_dir_;
        mutable std::mutex mutex_;
        bool loaded_{false};
        std::filesystem::path metadata_path(const std::string &transfer_id) const;

        void load_existing();
        void persist_state(const UploadState &state) const;
        void remove_state(const std::string &transfer_id);

        std::string generate_transfer_id();

        std::unordered_map<std::string, UploadState> uploads_;
    };

} // namespace minidrive::server
