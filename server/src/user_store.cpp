#include "minidrive/server/user_store.hpp"

#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

#include "minidrive/crypto.hpp"

namespace minidrive::server
{

    namespace
    {
        constexpr auto kMetadataDir = ".minidrive";
        constexpr auto kUsersFile = "users.json";
        constexpr auto kUsersRoot = "users";
    } // namespace

    UserStore::UserStore(std::filesystem::path root_directory)
        : storage_dir_(std::move(root_directory)),
          database_path_(storage_dir_ / kMetadataDir / kUsersFile)
    {
        std::filesystem::create_directories(storage_dir_ / kMetadataDir);
        std::filesystem::create_directories(storage_dir_ / kUsersRoot);
    }

    std::filesystem::path UserStore::users_root() const
    {
        return storage_dir_ / kUsersRoot;
    }

    bool UserStore::authenticate(const std::string &username, const std::string &password) const
    {
        std::lock_guard lock(mutex_);
        load_locked();
        const auto it = users_.find(username);
        if (it == users_.end())
        {
            return false;
        }
        return crypto::verify_password(password, it->second);
    }

    bool UserStore::register_user(const std::string &username, const std::string &password, std::string &message)
    {
        std::lock_guard lock(mutex_);
        load_locked();
        if (users_.contains(username))
        {
            message = "User already exists";
            return false;
        }
        const auto hash = crypto::hash_password(password);
        users_.emplace(username, hash);
        persist_locked();
        std::filesystem::create_directories(users_root() / username);
        message.clear();
        return true;
    }

    void UserStore::load_locked() const
    {
        if (loaded_)
        {
            return;
        }
        users_.clear();
        if (std::filesystem::exists(database_path_))
        {
            std::ifstream in(database_path_);
            if (in.is_open())
            {
                nlohmann::json json;
                in >> json;
                if (json.is_object())
                {
                    for (const auto &[key, value] : json.items())
                    {
                        users_[key] = value.get<std::string>();
                    }
                }
            }
        }
        loaded_ = true;
    }

    void UserStore::persist_locked() const
    {
        nlohmann::json json = nlohmann::json::object();
        for (const auto &[user, hash] : users_)
        {
            json[user] = hash;
        }
        std::ofstream out(database_path_, std::ios::trunc);
        out << json.dump(2);
    }

} // namespace minidrive::server
