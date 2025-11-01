#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#include "minidrive/protocol.hpp"
#include "minidrive/error_codes.hpp"

namespace minidrive::server
{

    struct SessionPaths
    {
        std::string identity;
        bool public_mode{};
        std::filesystem::path root;
    };

    class FilesystemError : public std::runtime_error
    {
    public:
        FilesystemError(minidrive::ErrorCode code, std::string message);

        minidrive::ErrorCode code() const noexcept { return code_; }

    private:
        minidrive::ErrorCode code_;
    };

    class Filesystem
    {
    public:
        explicit Filesystem(std::filesystem::path root);

        std::filesystem::path root() const;

        SessionPaths prepare_session_paths(const std::string &identity, bool public_mode);

        std::filesystem::path resolve(const SessionPaths &session, const std::string &requested) const;

        std::filesystem::path resolve_for_new_entry(const SessionPaths &session, const std::string &requested) const;

        std::vector<minidrive::protocol::FileMetadata> list_directory(const SessionPaths &session,
                                                                      const std::string &path) const;

        minidrive::protocol::FileMetadata stat_path(const SessionPaths &session, const std::string &path) const;

        void create_directory(const SessionPaths &session, const std::string &path) const;
        void remove_directory(const SessionPaths &session, const std::string &path) const;
        void remove_file(const SessionPaths &session, const std::string &path) const;
        void move_path(const SessionPaths &session, const std::string &from, const std::string &to) const;
        void copy_path(const SessionPaths &session, const std::string &from, const std::string &to) const;

    private:
        std::filesystem::path base_;

        std::filesystem::path ensure_directory(const std::filesystem::path &path) const;
        std::filesystem::path sanitize(const std::filesystem::path &base, const std::string &requested,
                                       bool allow_create) const;
        static minidrive::protocol::FileMetadata metadata_from_status(const std::filesystem::path &user_root,
                                                                      const std::filesystem::directory_entry &entry);
        static minidrive::protocol::FileMetadata metadata_from_path(const std::filesystem::path &user_root,
                                                                    const std::filesystem::path &path);
    };

} // namespace minidrive::server
