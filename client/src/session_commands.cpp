#include "minidrive/client/session.hpp"

#include <filesystem>
#include <iostream>
#include <vector>

#include "minidrive/error_codes.hpp"
#include "minidrive/protocol.hpp"

namespace minidrive::client
{

    bool ClientSession::handle_list(const std::vector<std::string> &args)
    {
        std::string path = remote_cwd_;
        if (!args.empty())
        {
            path = resolve_remote_path(args[0]);
        }

        minidrive::protocol::ListRequest request{.path = path};
        auto response = rpc(minidrive::protocol::Command::List, request);
        if (response.kind == minidrive::protocol::ResponseKind::Error)
        {
            print_error(response);
            return true;
        }

        std::cout << "OK" << std::endl;
        const auto entries = response.payload.value("entries", nlohmann::json::array());
        for (const auto &entry : entries)
        {
            const auto metadata = entry.get<minidrive::protocol::FileMetadata>();
            std::cout << (metadata.is_directory ? "[DIR ] " : "[FILE] ") << metadata.path << "  (" << metadata.size
                      << " bytes)" << std::endl;
        }
        return true;
    }

    bool ClientSession::handle_stat(const std::vector<std::string> &args)
    {
        if (args.size() != 1)
        {
            std::cout << "ERROR: invalid_usage" << std::endl;
            std::cout << "Usage: STAT <path>" << std::endl;
            return true;
        }
        const auto path = resolve_remote_path(args[0]);
        minidrive::protocol::PathRequest request{.path = path};
        auto response = rpc(minidrive::protocol::Command::Stat, request);
        if (response.kind == minidrive::protocol::ResponseKind::Error)
        {
            print_error(response);
            return true;
        }
        const auto metadata = response.payload.at("metadata").get<minidrive::protocol::FileMetadata>();
        std::cout << "OK" << std::endl;
        std::cout << "Path: " << metadata.path << std::endl;
        std::cout << "Type: " << (metadata.is_directory ? "directory" : "file") << std::endl;
        std::cout << "Size: " << metadata.size << " bytes" << std::endl;
        if (metadata.content_hash)
        {
            std::cout << "Hash: " << *metadata.content_hash << std::endl;
        }
        return true;
    }

    bool ClientSession::handle_cd(const std::vector<std::string> &args)
    {
        if (args.size() != 1)
        {
            std::cout << "ERROR: invalid_usage" << std::endl;
            std::cout << "Usage: CD <path>" << std::endl;
            return true;
        }
        const auto path = resolve_remote_path(args[0]);
        minidrive::protocol::PathRequest request{.path = path};
        auto response = rpc(minidrive::protocol::Command::Stat, request);
        if (response.kind == minidrive::protocol::ResponseKind::Error)
        {
            print_error(response);
            return true;
        }
        const auto metadata = response.payload.at("metadata").get<minidrive::protocol::FileMetadata>();
        if (!metadata.is_directory)
        {
            std::cout << "ERROR: invalid_target" << std::endl;
            std::cout << "Remote path is not a directory." << std::endl;
            return true;
        }
        remote_cwd_ = normalize_remote(path);
        std::cout << "OK" << std::endl;
        return true;
    }

    bool ClientSession::handle_simple_path_command(minidrive::protocol::Command command,
                                                   const std::vector<std::string> &args, std::size_t expected_args)
    {
        if (args.size() != expected_args)
        {
            std::cout << "ERROR: invalid_usage" << std::endl;
            std::cout << "Usage: " << minidrive::protocol::to_string(command) << " <path>" << std::endl;
            return true;
        }
        const auto path = resolve_remote_path(args[0]);
        minidrive::protocol::PathRequest request{.path = path};
        auto response = rpc(command, request);
        if (response.kind == minidrive::protocol::ResponseKind::Error)
        {
            print_error(response);
            return true;
        }
        std::cout << "OK" << std::endl;
        return true;
    }

    bool ClientSession::handle_move_copy(minidrive::protocol::Command command, const std::vector<std::string> &args)
    {
        if (args.size() != 2)
        {
            std::cout << "ERROR: invalid_usage" << std::endl;
            std::cout << "Usage: " << minidrive::protocol::to_string(command) << " <src> <dst>" << std::endl;
            return true;
        }

        minidrive::protocol::MoveCopyRequest request{
            .source = resolve_remote_path(args[0]),
            .destination = resolve_remote_path(args[1]),
        };
        auto response = rpc(command, request);
        if (response.kind == minidrive::protocol::ResponseKind::Error)
        {
            print_error(response);
            return true;
        }
        std::cout << "OK" << std::endl;
        return true;
    }

} // namespace minidrive::client
