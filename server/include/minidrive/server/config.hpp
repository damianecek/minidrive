#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace minidrive::server
{

    struct ServerConfig
    {
        std::string address{"0.0.0.0"};
        std::uint16_t port{0};
        std::filesystem::path root;
        std::size_t worker_threads{0};
        std::chrono::seconds upload_timeout{std::chrono::seconds{3600}};
        std::optional<std::filesystem::path> log_file;
    };

} // namespace minidrive::server
