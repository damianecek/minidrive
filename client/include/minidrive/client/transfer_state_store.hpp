#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace minidrive::client
{

    class TransferStateStore
    {
    public:
        struct Entry
        {
            std::string type;
            std::string identity;
            std::filesystem::path local_path;
            std::string remote_path;
            std::uint64_t total_size{};
            std::uint64_t bytes_transferred{};
        };

        TransferStateStore();

        std::vector<Entry> pending_for_identity(const std::string &identity) const;

        void upsert_upload(const std::string &identity, const std::filesystem::path &local_path,
                           const std::string &remote_path, std::uint64_t total_size);

        void upsert_download(const std::string &identity, const std::filesystem::path &local_path,
                             const std::string &remote_path, std::uint64_t total_size, std::uint64_t bytes_transferred);

        void update_upload_progress(const std::string &identity, const std::filesystem::path &local_path,
                                    const std::string &remote_path, std::uint64_t bytes_transferred);

        void update_download_progress(const std::string &identity, const std::filesystem::path &local_path,
                                      const std::string &remote_path, std::uint64_t bytes_transferred);

        void remove_upload(const std::string &identity, const std::filesystem::path &local_path,
                           const std::string &remote_path);

        void remove_download(const std::string &identity, const std::filesystem::path &local_path,
                             const std::string &remote_path);

        void discard_identity(const std::string &identity);

    private:
        static std::filesystem::path default_state_path();
        void load();
        void save() const;
        void upsert(const std::string &type, const std::string &identity, const std::filesystem::path &local_path,
                    const std::string &remote_path, std::uint64_t total_size);
        void update_progress(const std::string &type, const std::string &identity, const std::filesystem::path &local_path,
                             const std::string &remote_path, std::uint64_t bytes_transferred);
        void remove_entry(const std::string &type, const std::string &identity, const std::filesystem::path &local_path,
                          const std::string &remote_path);
        std::vector<Entry>::iterator find_entry(const std::string &type, const std::string &identity,
                                                const std::filesystem::path &local_path, const std::string &remote_path);
        static std::filesystem::path normalize_path(const std::filesystem::path &path);

        std::filesystem::path state_path_;
        std::vector<Entry> entries_;
    };

} // namespace minidrive::client
