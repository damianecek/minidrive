#pragma once

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace minidrive::server
{

    class UserStore
    {
    public:
        explicit UserStore(std::filesystem::path root_directory);

        bool authenticate(const std::string &username, const std::string &password) const;
        bool register_user(const std::string &username, const std::string &password, std::string &message);

        std::filesystem::path users_root() const;

    private:
        void load_locked() const;
        void persist_locked() const;

        std::filesystem::path storage_dir_;
        std::filesystem::path database_path_;

        mutable std::mutex mutex_;
        mutable bool loaded_{false};
        mutable std::unordered_map<std::string, std::string> users_;
    };

} // namespace minidrive::server
