#include "minidrive/client/session.hpp"

#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <set>

#include "minidrive/crypto.hpp"
#include "minidrive/protocol.hpp"

namespace minidrive::client
{

    bool ClientSession::handle_sync(const std::vector<std::string> &args)
    {
        if (args.size() != 2)
        {
            std::cout << "ERROR: invalid_usage" << std::endl;
            std::cout << "Usage: SYNC <local_dir> <remote_dir>" << std::endl;
            return true;
        }

        const auto local_root = std::filesystem::absolute(std::filesystem::path(args[0]));
        if (!std::filesystem::exists(local_root) || !std::filesystem::is_directory(local_root))
        {
            std::cout << "ERROR: invalid_target" << std::endl;
            std::cout << "Local path must be an existing directory." << std::endl;
            return true;
        }

        std::string remote_root = resolve_remote_path(args[1]);
        if (!ensure_remote_directory(remote_root))
        {
            return true;
        }

        const auto local_snapshot = build_local_snapshot(local_root);
        const auto remote_snapshot = build_remote_snapshot(remote_root);

        std::set<std::string> remote_directories;
        for (const auto &[path, entry] : remote_snapshot)
        {
            if (entry.is_directory)
            {
                remote_directories.insert(path);
            }
        }

        std::set<std::string> created_directories;
        auto ensure_remote_dirs_for_path = [&](const std::string &relative_path)
        {
            std::filesystem::path rel(relative_path);
            if (rel.has_parent_path())
            {
                auto parent = rel.parent_path();
                if (!parent.empty() && parent != ".")
                {
                    const auto parent_str = parent.generic_string();
                    if (created_directories.insert(parent_str).second &&
                        remote_directories.find(parent_str) == remote_directories.end())
                    {
                        if (ensure_remote_directory(join_remote_path(remote_root, parent_str)))
                        {
                            remote_directories.insert(parent_str);
                        }
                    }
                }
            }
        };

        std::size_t uploads = 0;
        std::size_t deletes = 0;
        std::size_t skipped = 0;

        for (const auto &[path, entry] : local_snapshot)
        {
            if (path == ".")
            {
                continue;
            }
            if (entry.is_directory)
            {
                if (remote_snapshot.find(path) == remote_snapshot.end())
                {
                    if (ensure_remote_directory(join_remote_path(remote_root, path)))
                    {
                        remote_directories.insert(path);
                    }
                }
                continue;
            }

            const auto remote_it = remote_snapshot.find(path);
            const bool needs_upload = (remote_it == remote_snapshot.end()) || remote_it->second.hash != entry.hash;
            if (!needs_upload)
            {
                ++skipped;
                continue;
            }
            ensure_remote_dirs_for_path(path);
            if (perform_upload(local_root / path, join_remote_path(remote_root, path), false))
            {
                ++uploads;
            }
        }

        minidrive::protocol::SyncPlan plan;
        for (const auto &[path, entry] : remote_snapshot)
        {
            if (path == ".")
            {
                continue;
            }
            if (local_snapshot.find(path) == local_snapshot.end())
            {
                minidrive::protocol::SyncDiffEntry diff;
                diff.action = minidrive::protocol::SyncAction::DeleteRemote;
                diff.metadata.path = join_remote_path(remote_root, path);
                diff.metadata.is_directory = entry.is_directory;
                diff.metadata.size = entry.size;
                diff.metadata.content_hash = entry.hash.empty() ? std::optional<std::string>{}
                                                                : std::optional<std::string>(entry.hash);
                plan.entries.push_back(std::move(diff));
            }
        }

        if (!plan.entries.empty())
        {
            auto response = rpc(minidrive::protocol::Command::SyncApply, nlohmann::json(plan));
            if (response.kind == minidrive::protocol::ResponseKind::Error)
            {
                print_error(response);
            }
            else
            {
                deletes = plan.entries.size();
            }
        }

        std::cout << "OK" << std::endl;
        std::cout << "Uploaded: " << uploads << std::endl;
        std::cout << "Deleted: " << deletes << std::endl;
        std::cout << "Unchanged: " << skipped << std::endl;
        return true;
    }

    std::map<std::string, ClientSession::SnapshotEntry>
    ClientSession::build_local_snapshot(const std::filesystem::path &root)
    {
        std::map<std::string, SnapshotEntry> snapshot;
        snapshot["."] = SnapshotEntry{.is_directory = true, .size = 0, .hash = {}};
        for (std::filesystem::recursive_directory_iterator it(root); it != std::filesystem::recursive_directory_iterator(); ++it)
        {
            auto rel = std::filesystem::relative(it->path(), root);
            std::string relative = rel.empty() ? std::string(".") : rel.generic_string();
            SnapshotEntry entry{};
            entry.is_directory = it->is_directory();
            if (!entry.is_directory)
            {
                entry.size = it->file_size();
                entry.hash = minidrive::crypto::hash_file(it->path());
            }
            snapshot[relative] = std::move(entry);
        }
        return snapshot;
    }

    std::map<std::string, ClientSession::SnapshotEntry>
    ClientSession::build_remote_snapshot(const std::string &remote_root)
    {
        std::map<std::string, SnapshotEntry> snapshot;
        minidrive::protocol::PathRequest request{.path = remote_root};
        auto response = rpc(minidrive::protocol::Command::SyncEnumerate, request);
        if (response.kind == minidrive::protocol::ResponseKind::Error)
        {
            print_error(response);
            return snapshot;
        }
        const auto entries = response.payload.value("entries", nlohmann::json::array());
        for (const auto &item : entries)
        {
            const auto metadata = item.get<minidrive::protocol::FileMetadata>();
            SnapshotEntry entry{};
            entry.is_directory = metadata.is_directory;
            entry.size = metadata.size;
            if (metadata.content_hash)
            {
                entry.hash = *metadata.content_hash;
            }
            snapshot[metadata.path] = std::move(entry);
        }
        if (snapshot.find(".") == snapshot.end())
        {
            snapshot["."] = SnapshotEntry{.is_directory = true, .size = 0, .hash = {}};
        }
        return snapshot;
    }

} // namespace minidrive::client
