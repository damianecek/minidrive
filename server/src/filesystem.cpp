#include "minidrive/server/filesystem.hpp"

#include <chrono>
#include <filesystem>
#include <stdexcept>

namespace minidrive::server
{

    FilesystemError::FilesystemError(minidrive::ErrorCode code, std::string message)
        : std::runtime_error(std::move(message)), code_(code) {}

    namespace
    {
        constexpr auto kPublicDir = "public";
        constexpr auto kUsersDir = "users";

        std::uint64_t to_unix_time(const std::filesystem::file_time_type &time)
        {
            using namespace std::chrono;
            const auto sctp = time_point_cast<seconds>(time - std::filesystem::file_time_type::clock::now() +
                                                       std::chrono::system_clock::now());
            return static_cast<std::uint64_t>(sctp.time_since_epoch().count());
        }

        std::string relative_string(const std::filesystem::path &base, const std::filesystem::path &path)
        {
            auto rel = path.lexically_relative(base);
            auto string_form = rel.generic_string();
            if (string_form.empty())
            {
                return ".";
            }
            return string_form;
        }

    } // namespace

    Filesystem::Filesystem(std::filesystem::path root) : base_(std::move(root))
    {
        std::filesystem::create_directories(base_);
        std::filesystem::create_directories(base_ / kPublicDir);
        std::filesystem::create_directories(base_ / kUsersDir);
    }

    std::filesystem::path Filesystem::root() const
    {
        return base_;
    }

    SessionPaths Filesystem::prepare_session_paths(const std::string &identity, bool public_mode)
    {
        SessionPaths paths{
            .identity = identity,
            .public_mode = public_mode,
            .root = public_mode ? (base_ / kPublicDir) : (base_ / kUsersDir / identity),
        };
        std::filesystem::create_directories(paths.root);
        return paths;
    }

    std::filesystem::path Filesystem::resolve(const SessionPaths &session, const std::string &requested) const
    {
        const auto path = sanitize(session.root, requested, false);
        if (!std::filesystem::exists(path))
        {
            throw FilesystemError(minidrive::ErrorCode::NotFound, "Path does not exist");
        }
        return path;
    }

    std::filesystem::path Filesystem::resolve_for_new_entry(const SessionPaths &session,
                                                            const std::string &requested) const
    {
        return sanitize(session.root, requested, true);
    }

    std::vector<minidrive::protocol::FileMetadata> Filesystem::list_directory(const SessionPaths &session,
                                                                              const std::string &path) const
    {
        const auto target = resolve(session, path);
        if (!std::filesystem::is_directory(target))
        {
            throw std::runtime_error("Target is not a directory");
        }
        std::vector<minidrive::protocol::FileMetadata> entries;
        for (const auto &entry : std::filesystem::directory_iterator(target))
        {
            entries.push_back(metadata_from_status(session.root, entry));
        }
        return entries;
    }

    minidrive::protocol::FileMetadata Filesystem::stat_path(const SessionPaths &session,
                                                            const std::string &path) const
    {
        const auto target = resolve(session, path);
        return metadata_from_path(session.root, target);
    }

    void Filesystem::create_directory(const SessionPaths &session, const std::string &path) const
    {
        const auto target = resolve_for_new_entry(session, path);
        std::filesystem::create_directories(target);
    }

    void Filesystem::remove_directory(const SessionPaths &session, const std::string &path) const
    {
        const auto target = resolve(session, path);
        if (!std::filesystem::is_directory(target))
        {
            throw FilesystemError(minidrive::ErrorCode::InvalidPayload, "Target is not a directory");
        }
        std::filesystem::remove_all(target);
    }

    void Filesystem::remove_file(const SessionPaths &session, const std::string &path) const
    {
        const auto target = resolve(session, path);
        if (std::filesystem::is_directory(target))
        {
            throw FilesystemError(minidrive::ErrorCode::InvalidPayload, "Target is a directory");
        }
        std::filesystem::remove(target);
    }

    void Filesystem::move_path(const SessionPaths &session, const std::string &from, const std::string &to) const
    {
        const auto source = resolve(session, from);
        const auto destination = resolve_for_new_entry(session, to);
        std::filesystem::create_directories(destination.parent_path());
        std::filesystem::rename(source, destination);
    }

    void Filesystem::copy_path(const SessionPaths &session, const std::string &from, const std::string &to) const
    {
        const auto source = resolve(session, from);
        const auto destination = resolve_for_new_entry(session, to);
        std::filesystem::create_directories(destination.parent_path());
        const auto options = std::filesystem::copy_options::overwrite_existing |
                             (std::filesystem::is_directory(source) ? std::filesystem::copy_options::recursive
                                                                    : std::filesystem::copy_options::none);
        std::filesystem::copy(source, destination, options);
    }

    std::filesystem::path Filesystem::ensure_directory(const std::filesystem::path &path) const
    {
        std::filesystem::create_directories(path);
        return path;
    }

    std::filesystem::path Filesystem::sanitize(const std::filesystem::path &base, const std::string &requested,
                                               bool /*allow_create*/) const
    {
        std::filesystem::path relative = requested;
        if (!requested.empty() && relative.is_absolute())
        {
            relative = relative.lexically_relative("/");
        }

        std::filesystem::path sanitized = base;
        for (const auto &part : relative)
        {
            const auto part_string = part.generic_string();
            if (part_string.empty() || part_string == ".")
            {
                continue;
            }
            if (part_string == "..")
            {
                throw std::runtime_error("Path traversal detected");
            }
            sanitized /= part;
        }
        return sanitized;
    }

    minidrive::protocol::FileMetadata Filesystem::metadata_from_status(const std::filesystem::path &user_root,
                                                                       const std::filesystem::directory_entry &entry)
    {
        minidrive::protocol::FileMetadata metadata{};
        metadata.path = relative_string(user_root, entry.path());
        metadata.is_directory = entry.is_directory();
        metadata.size = metadata.is_directory ? 0 : entry.file_size();
        metadata.modified_time = to_unix_time(entry.last_write_time());
        return metadata;
    }

    minidrive::protocol::FileMetadata Filesystem::metadata_from_path(const std::filesystem::path &user_root,
                                                                     const std::filesystem::path &path)
    {
        minidrive::protocol::FileMetadata metadata{};
        metadata.path = relative_string(user_root, path);
        metadata.is_directory = std::filesystem::is_directory(path);
        metadata.size = metadata.is_directory ? 0 : std::filesystem::file_size(path);
        metadata.modified_time = to_unix_time(std::filesystem::last_write_time(path));
        return metadata;
    }

} // namespace minidrive::server
