#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace minidrive::client
{

    struct ClientConfig
    {
        std::optional<std::string> username;
        std::string host;
        std::uint16_t port{};
        std::optional<std::filesystem::path> log_path;
        std::optional<std::size_t> max_upload_rate;
        std::optional<std::size_t> max_download_rate;
    };

    ClientConfig parse_arguments(int argc, char *argv[]);

} // namespace minidrive::client
