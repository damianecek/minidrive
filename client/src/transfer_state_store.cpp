#include "minidrive/client/transfer_state_store.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>

#include <nlohmann/json.hpp>

namespace minidrive::client
{

    TransferStateStore::TransferStateStore()
    {
        load();
    }

    std::vector<TransferStateStore::Entry> TransferStateStore::pending_for_identity(const std::string &identity) const
    {
        std::vector<Entry> result;
        for (const auto &entry : entries_)
        {
            if (entry.identity == identity)
            {
                result.push_back(entry);
            }
        }
        return result;
    }

    void TransferStateStore::upsert_upload(const std::string &identity, const std::filesystem::path &local_path,
                                           const std::string &remote_path, std::uint64_t total_size)
    {
        upsert("upload", identity, local_path, remote_path, total_size);
    }

    void TransferStateStore::upsert_download(const std::string &identity, const std::filesystem::path &local_path,
                                             const std::string &remote_path, std::uint64_t total_size,
                                             std::uint64_t bytes_transferred)
    {
        upsert("download", identity, local_path, remote_path, total_size);
        update_progress("download", identity, local_path, remote_path, bytes_transferred);
    }

    void TransferStateStore::update_upload_progress(const std::string &identity, const std::filesystem::path &local_path,
                                                    const std::string &remote_path, std::uint64_t bytes_transferred)
    {
        update_progress("upload", identity, local_path, remote_path, bytes_transferred);
    }

    void TransferStateStore::update_download_progress(const std::string &identity, const std::filesystem::path &local_path,
                                                      const std::string &remote_path, std::uint64_t bytes_transferred)
    {
        update_progress("download", identity, local_path, remote_path, bytes_transferred);
    }

    void TransferStateStore::remove_upload(const std::string &identity, const std::filesystem::path &local_path,
                                           const std::string &remote_path)
    {
        remove_entry("upload", identity, local_path, remote_path);
    }

    void TransferStateStore::remove_download(const std::string &identity, const std::filesystem::path &local_path,
                                             const std::string &remote_path)
    {
        remove_entry("download", identity, local_path, remote_path);
    }

    void TransferStateStore::discard_identity(const std::string &identity)
    {
        entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [&](const Entry &entry)
                                      { return entry.identity == identity; }),
                       entries_.end());
        save();
    }

    std::filesystem::path TransferStateStore::default_state_path()
    {
#ifdef _WIN32
        if (const char *appdata = std::getenv("APPDATA"))
        {
            return std::filesystem::path(appdata) / "MiniDrive" / "transfers.json";
        }
#endif
        if (const char *home = std::getenv("HOME"))
        {
            return std::filesystem::path(home) / ".minidrive" / "transfers.json";
        }
        return std::filesystem::path(".minidrive") / "transfers.json";
    }

    void TransferStateStore::load()
    {
        state_path_ = default_state_path();
        entries_.clear();
        if (!std::filesystem::exists(state_path_))
        {
            return;
        }
        std::ifstream in(state_path_);
        if (!in.is_open())
        {
            return;
        }
        nlohmann::json json;
        in >> json;
        if (!json.is_array())
        {
            return;
        }
        for (const auto &item : json)
        {
            Entry entry;
            entry.type = item.value("type", std::string{});
            entry.identity = item.value("identity", std::string{});
            entry.local_path = normalize_path(std::filesystem::path(item.value("local", std::string{})));
            entry.remote_path = item.value("remote", std::string{});
            entry.total_size = item.value("total", 0ULL);
            entry.bytes_transferred = item.value("bytes", 0ULL);
            if (!entry.type.empty() && !entry.identity.empty())
            {
                entries_.push_back(std::move(entry));
            }
        }
    }

    void TransferStateStore::save() const
    {
        const auto dir = state_path_.parent_path();
        if (!dir.empty())
        {
            std::error_code ec;
            std::filesystem::create_directories(dir, ec);
        }
        nlohmann::json json = nlohmann::json::array();
        for (const auto &entry : entries_)
        {
            json.push_back({{"type", entry.type},
                            {"identity", entry.identity},
                            {"local", entry.local_path.generic_string()},
                            {"remote", entry.remote_path},
                            {"total", entry.total_size},
                            {"bytes", entry.bytes_transferred}});
        }
        std::ofstream out(state_path_, std::ios::trunc);
        if (out.is_open())
        {
            out << json.dump(2);
        }
    }

    void TransferStateStore::upsert(const std::string &type, const std::string &identity,
                                    const std::filesystem::path &local_path, const std::string &remote_path,
                                    std::uint64_t total_size)
    {
        auto normalized_local = normalize_path(local_path);
        auto it = find_entry(type, identity, normalized_local, remote_path);
        if (it == entries_.end())
        {
            entries_.push_back(Entry{type, identity, normalized_local, remote_path, total_size, 0});
        }
        else
        {
            it->total_size = total_size;
        }
        save();
    }

    void TransferStateStore::update_progress(const std::string &type, const std::string &identity,
                                             const std::filesystem::path &local_path, const std::string &remote_path,
                                             std::uint64_t bytes_transferred)
    {
        auto it = find_entry(type, identity, normalize_path(local_path), remote_path);
        if (it != entries_.end())
        {
            it->bytes_transferred = bytes_transferred;
            save();
        }
    }

    void TransferStateStore::remove_entry(const std::string &type, const std::string &identity,
                                          const std::filesystem::path &local_path, const std::string &remote_path)
    {
        auto it = find_entry(type, identity, normalize_path(local_path), remote_path);
        if (it != entries_.end())
        {
            entries_.erase(it);
            save();
        }
    }

    std::vector<TransferStateStore::Entry>::iterator TransferStateStore::find_entry(
        const std::string &type, const std::string &identity, const std::filesystem::path &local_path,
        const std::string &remote_path)
    {
        return std::find_if(entries_.begin(), entries_.end(), [&](const Entry &entry)
                            { return entry.type == type && entry.identity == identity &&
                                     entry.local_path == local_path && entry.remote_path == remote_path; });
    }

    std::filesystem::path TransferStateStore::normalize_path(const std::filesystem::path &path)
    {
        std::error_code ec;
        auto absolute = std::filesystem::absolute(path, ec);
        if (ec)
        {
            absolute = path;
        }
        return absolute.lexically_normal();
    }

} // namespace minidrive::client
