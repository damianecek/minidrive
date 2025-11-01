#include "minidrive/client/config.hpp"

#include <filesystem>
#include <stdexcept>
#include <string>

namespace minidrive::client
{

    ClientConfig parse_arguments(int argc, char *argv[])
    {
        if (argc < 2)
        {
            throw std::runtime_error("Usage: client [username@]<server>:<port> [--log <file>]");
        }

        ClientConfig config;
        int index = 1;
        const std::string endpoint = argv[index++];

        const auto at_pos = endpoint.find('@');
        std::string host_part = endpoint;
        if (at_pos != std::string::npos)
        {
            config.username = endpoint.substr(0, at_pos);
            host_part = endpoint.substr(at_pos + 1);
        }

        const auto colon_pos = host_part.find(':');
        if (colon_pos == std::string::npos)
        {
            throw std::runtime_error("Expected endpoint format host:port");
        }
        config.host = host_part.substr(0, colon_pos);
        const auto port_string = host_part.substr(colon_pos + 1);
        config.port = static_cast<std::uint16_t>(std::stoi(port_string));

        while (index < argc)
        {
            const std::string arg = argv[index++];
            if (arg == "--log")
            {
                if (index >= argc)
                {
                    throw std::runtime_error("--log requires a file path");
                }
                config.log_path = std::filesystem::path(argv[index++]);
            }
            else if (arg == "--max-upload-rate")
            {
                if (index >= argc)
                {
                    throw std::runtime_error("--max-upload-rate requires a value (bytes per second)");
                }
                config.max_upload_rate = static_cast<std::size_t>(std::stoull(argv[index++]));
            }
            else if (arg == "--max-download-rate")
            {
                if (index >= argc)
                {
                    throw std::runtime_error("--max-download-rate requires a value (bytes per second)");
                }
                config.max_download_rate = static_cast<std::size_t>(std::stoull(argv[index++]));
            }
            else
            {
                throw std::runtime_error("Unknown argument: " + arg);
            }
        }

        return config;
    }

} // namespace minidrive::client
