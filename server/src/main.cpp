#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "minidrive/server/server.hpp"
#include "minidrive/version.hpp"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace
{

    void print_usage(const char *program_name)
    {
        std::cout << "MiniDrive server " << minidrive::version() << "\n"
                  << "Usage: " << program_name
                  << " --port <PORT> --root <ROOT> [--address <ADDRESS>] [--threads <N>] [--upload-timeout <seconds>] "
                     "[--log <FILE>]\n";
    }

    std::optional<std::string> read_option(int &index, int argc, char *argv[])
    {
        if (index + 1 >= argc)
        {
            return std::nullopt;
        }
        ++index;
        return std::string(argv[index]);
    }

} // namespace

int main(int argc, char *argv[])
{
    using minidrive::server::Server;
    using minidrive::server::ServerConfig;

    ServerConfig config;

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--port")
        {
            auto value = read_option(i, argc, argv);
            if (!value)
            {
                std::cerr << "Missing value for --port" << std::endl;
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            config.port = static_cast<std::uint16_t>(std::stoi(*value));
        }
        else if (arg == "--root")
        {
            auto value = read_option(i, argc, argv);
            if (!value)
            {
                std::cerr << "Missing value for --root" << std::endl;
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            config.root = std::filesystem::path(*value);
        }
        else if (arg == "--address")
        {
            auto value = read_option(i, argc, argv);
            if (!value)
            {
                std::cerr << "Missing value for --address" << std::endl;
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            config.address = *value;
        }
        else if (arg == "--threads")
        {
            auto value = read_option(i, argc, argv);
            if (!value)
            {
                std::cerr << "Missing value for --threads" << std::endl;
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            config.worker_threads = static_cast<std::size_t>(std::stoul(*value));
        }
        else if (arg == "--upload-timeout")
        {
            auto value = read_option(i, argc, argv);
            if (!value)
            {
                std::cerr << "Missing value for --upload-timeout" << std::endl;
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            config.upload_timeout = std::chrono::seconds(std::stoll(*value));
        }
        else if (arg == "--log")
        {
            auto value = read_option(i, argc, argv);
            if (!value)
            {
                std::cerr << "Missing value for --log" << std::endl;
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            config.log_file = std::filesystem::path(*value);
        }
        else if (arg == "--help" || arg == "-h")
        {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        else
        {
            std::cerr << "Unknown argument: " << arg << std::endl;
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (config.port == 0 || config.root.empty())
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    try
    {
        std::vector<spdlog::sink_ptr> sinks;
        sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
        if (config.log_file)
        {
            sinks.push_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(config.log_file->string(), true));
        }
        auto logger = std::make_shared<spdlog::logger>("server", sinks.begin(), sinks.end());
        logger->set_level(spdlog::level::info);
        logger->set_pattern("%Y-%m-%d %H:%M:%S [%^%l%$] %v");
        spdlog::set_default_logger(logger);
        spdlog::info("Starting MiniDrive server {} on {}:{}", minidrive::version(), config.address, config.port);

        Server server(std::move(config));
        server.run();
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Server failed: " << ex.what() << std::endl;
        spdlog::error("Fatal error: {}", ex.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
