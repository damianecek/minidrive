#include <asio.hpp>

#include <chrono>
#include <cstdlib>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <cstring>
#include <tuple>
#include <utility>
#include <vector>

#include <thread>

#include <nlohmann/json.hpp>

#include "minidrive/crypto.hpp"
#include "minidrive/error_codes.hpp"
#include "minidrive/framing.hpp"
#include "minidrive/protocol.hpp"
#include "minidrive/version.hpp"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

namespace
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

    class Logger
    {
    public:
        explicit Logger(const std::optional<std::filesystem::path> &path)
        {
            try
            {
                std::vector<spdlog::sink_ptr> sinks;
                if (path)
                {
                    sinks.push_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(path->string(), true));
                }
                else
                {
                    sinks.push_back(std::make_shared<spdlog::sinks::null_sink_mt>());
                }
                logger_ = std::make_shared<spdlog::logger>("client", sinks.begin(), sinks.end());
                logger_->set_pattern("%Y-%m-%d %H:%M:%S [%l] %v");
                logger_->set_level(spdlog::level::info);
            }
            catch (...)
            {
                logger_.reset();
            }
        }

        template <typename... Args>
        void log(const std::string &tag, Args &&...args)
        {
            if (!logger_)
            {
                return;
            }
            spdlog::fmt_lib::memory_buffer buf;
            (spdlog::fmt_lib::format_to(std::back_inserter(buf), "{}", std::forward<Args>(args)), ...);
            logger_->info("[{}] {}", tag,
                          std::string(buf.data(), buf.size()));
        }

    private:
        std::shared_ptr<spdlog::logger> logger_;
    };

    class TransferStateStore
    {
    public:
        struct Entry
        {
            std::string type; // "upload" or "download"
            std::string identity;
            std::filesystem::path local_path;
            std::string remote_path;
            std::uint64_t total_size{};
            std::uint64_t bytes_transferred{};
        };

        TransferStateStore()
        {
            load();
        }

        std::vector<Entry> pending_for_identity(const std::string &identity) const
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

        void upsert_upload(const std::string &identity, const std::filesystem::path &local_path,
                           const std::string &remote_path, std::uint64_t total_size)
        {
            upsert("upload", identity, local_path, remote_path, total_size);
        }

        void upsert_download(const std::string &identity, const std::filesystem::path &local_path,
                             const std::string &remote_path, std::uint64_t total_size, std::uint64_t bytes_transferred)
        {
            upsert("download", identity, local_path, remote_path, total_size);
            update_progress("download", identity, local_path, remote_path, bytes_transferred);
        }

        void update_upload_progress(const std::string &identity, const std::filesystem::path &local_path,
                                    const std::string &remote_path, std::uint64_t bytes_transferred)
        {
            update_progress("upload", identity, local_path, remote_path, bytes_transferred);
        }

        void update_download_progress(const std::string &identity, const std::filesystem::path &local_path,
                                      const std::string &remote_path, std::uint64_t bytes_transferred)
        {
            update_progress("download", identity, local_path, remote_path, bytes_transferred);
        }

        void remove_upload(const std::string &identity, const std::filesystem::path &local_path,
                           const std::string &remote_path)
        {
            remove_entry("upload", identity, local_path, remote_path);
        }

        void remove_download(const std::string &identity, const std::filesystem::path &local_path,
                             const std::string &remote_path)
        {
            remove_entry("download", identity, local_path, remote_path);
        }

        void discard_identity(const std::string &identity)
        {
            entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [&](const Entry &entry)
                                          { return entry.identity == identity; }),
                           entries_.end());
            save();
        }

    private:
        static std::filesystem::path default_state_path()
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

        void load()
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

        void save() const
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

        void upsert(const std::string &type, const std::string &identity, const std::filesystem::path &local_path,
                    const std::string &remote_path, std::uint64_t total_size)
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

        void update_progress(const std::string &type, const std::string &identity, const std::filesystem::path &local_path,
                             const std::string &remote_path, std::uint64_t bytes_transferred)
        {
            auto it = find_entry(type, identity, normalize_path(local_path), remote_path);
            if (it != entries_.end())
            {
                it->bytes_transferred = bytes_transferred;
                save();
            }
        }

        void remove_entry(const std::string &type, const std::string &identity, const std::filesystem::path &local_path,
                          const std::string &remote_path)
        {
            auto it = find_entry(type, identity, normalize_path(local_path), remote_path);
            if (it != entries_.end())
            {
                entries_.erase(it);
                save();
            }
        }

        std::vector<Entry>::iterator find_entry(const std::string &type, const std::string &identity,
                                                const std::filesystem::path &local_path, const std::string &remote_path)
        {
            return std::find_if(entries_.begin(), entries_.end(), [&](const Entry &entry)
                                { return entry.type == type && entry.identity == identity &&
                                         entry.local_path == local_path && entry.remote_path == remote_path; });
        }

        static std::filesystem::path normalize_path(const std::filesystem::path &path)
        {
            std::error_code ec;
            auto absolute = std::filesystem::absolute(path, ec);
            if (ec)
            {
                absolute = path;
            }
            return absolute.lexically_normal();
        }

        std::filesystem::path state_path_;
        std::vector<Entry> entries_;
    };

    std::string trim(const std::string &input)
    {
        const auto begin = input.find_first_not_of(" \t\r\n");
        if (begin == std::string::npos)
        {
            return "";
        }
        const auto end = input.find_last_not_of(" \t\r\n");
        return input.substr(begin, end - begin + 1);
    }

    std::vector<std::string> split_tokens(const std::string &input)
    {
        std::vector<std::string> tokens;
        std::istringstream iss(input);
        std::string token;
        while (iss >> token)
        {
            tokens.push_back(token);
        }
        return tokens;
    }

    std::string to_upper(std::string value)
    {
        for (auto &ch : value)
        {
            ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        }
        return value;
    }

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

    std::string encode_base64(std::span<const std::byte> data)
    {
        static constexpr char kAlphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::string output;
        output.reserve(((data.size() + 2) / 3) * 4);

        std::uint32_t buffer = 0;
        int bits_collected = 0;

        for (const auto byte : data)
        {
            buffer = (buffer << 8u) | static_cast<std::uint32_t>(byte);
            bits_collected += 8;
            while (bits_collected >= 6)
            {
                bits_collected -= 6;
                const auto index = static_cast<std::size_t>((buffer >> bits_collected) & 0x3Fu);
                output.push_back(kAlphabet[index]);
            }
        }

        if (bits_collected > 0)
        {
            buffer <<= (6 - bits_collected);
            const auto index = static_cast<std::size_t>(buffer & 0x3F);
            output.push_back(kAlphabet[index]);
        }

        while (output.size() % 4 != 0)
        {
            output.push_back('=');
        }

        return output;
    }

    std::vector<std::byte> decode_base64(const std::string &input)
    {
        static const auto table = []
        {
            std::array<int8_t, 256> t{};
            t.fill(-1);
            const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            for (std::size_t i = 0; i < alphabet.size(); ++i)
            {
                t[static_cast<unsigned char>(alphabet[i])] = static_cast<int8_t>(i);
            }
            t[static_cast<unsigned char>('=')] = -2;
            return t;
        }();

        std::vector<std::byte> output;
        output.reserve((input.size() * 3) / 4);

        std::uint32_t accumulator = 0;
        int bits_collected = 0;
        for (const char ch : input)
        {
            const unsigned char c = static_cast<unsigned char>(ch);
            const int value = table[c];
            if (value == -1)
            {
                if (!std::isspace(static_cast<unsigned char>(c)))
                {
                    return {};
                }
                continue;
            }
            if (value == -2)
            {
                break;
            }
            accumulator = (accumulator << 6) | static_cast<std::uint32_t>(value);
            bits_collected += 6;
            if (bits_collected >= 8)
            {
                bits_collected -= 8;
                const auto byte_value = static_cast<std::uint8_t>((accumulator >> bits_collected) & 0xFFu);
                output.push_back(static_cast<std::byte>(byte_value));
            }
        }

        return output;
    }

    void apply_rate_limit(const std::optional<std::size_t> &rate, std::size_t bytes,
                          const std::chrono::steady_clock::time_point &start_time)
    {
        if (!rate || *rate == 0 || bytes == 0)
        {
            return;
        }
        const double expected_seconds = static_cast<double>(bytes) / static_cast<double>(*rate);
        const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_time).count();
        if (elapsed < expected_seconds)
        {
            std::this_thread::sleep_for(std::chrono::duration<double>(expected_seconds - elapsed));
        }
    }

    class ClientSession
    {
    public:
        ClientSession(ClientConfig config, Logger logger)
            : config_(std::move(config)),
              logger_(std::move(logger)),
              state_store_(),
              socket_(io_context_) {}

        int run()
        {
            try
            {
                connect();
                authenticate();
                interactive_shell();
            }
            catch (const std::exception &ex)
            {
                std::cerr << "ERROR: " << ex.what() << std::endl;
                logger_.log("error", "fatal: ", ex.what());
                return 1;
            }
            return 0;
        }

    private:
        struct SnapshotEntry
        {
            bool is_directory{};
            std::uint64_t size{};
            std::string hash;
        };

        void connect()
        {
            asio::ip::tcp::resolver resolver(io_context_);
            const auto results = resolver.resolve(config_.host, std::to_string(config_.port));
            asio::connect(socket_, results);
            logger_.log("info", "connected to ", config_.host, ':', config_.port);
        }

        static std::string prompt_password(const std::string &username)
        {
            std::string password;
            std::cout << "Password for " << username << ": " << std::flush;
            std::getline(std::cin, password);
            return password;
        }

        bool ask_yes_no(const std::string &question) const
        {
            while (true)
            {
                std::cout << question << " (y/n): " << std::flush;
                std::string answer;
                if (!std::getline(std::cin, answer))
                {
                    return false;
                }
                answer = trim(to_upper(answer));
                if (answer == "Y" || answer == "YES")
                {
                    return true;
                }
                if (answer == "N" || answer == "NO")
                {
                    return false;
                }
                std::cout << "Please answer y or n." << std::endl;
            }
        }

        void authenticate()
        {
            minidrive::protocol::AuthenticateRequest request{};
            request.public_mode = !config_.username.has_value();
            request.username = config_.username.value_or("");
            request.password.clear();
            request.register_user = false;

            if (request.public_mode)
            {
                std::cout << "[warning] operating in public mode - files are visible to everyone" << std::endl;
            }
            else
            {
                request.password = prompt_password(request.username);
            }

            for (;;)
            {
                auto response = rpc(minidrive::protocol::Command::Authenticate, request);
                if (response.kind == minidrive::protocol::ResponseKind::Ok)
                {
                    const auto auth = response.payload.get<minidrive::protocol::AuthenticateResponse>();
                    identity_ = auth.identity;
                    std::cout << "Logged as " << identity_ << std::endl;
                    logger_.log("info", "authenticated as ", identity_);
                    resume_pending_transfers();
                    return;
                }

                if (request.public_mode)
                {
                    throw std::runtime_error("Authentication failed in public mode: " + response.message);
                }

                std::cout << "Authentication failed: " << response.message << std::endl;
                const bool want_register = ask_yes_no("User " + request.username + " not found. Register?");
                if (!want_register)
                {
                    throw std::runtime_error("Unable to authenticate user");
                }
                request.register_user = true;
                request.password = prompt_password(request.username);
            }
        }

        void interactive_shell()
        {
            while (true)
            {
                std::cout << identity_prompt() << "> " << std::flush;
                std::string line;
                if (!std::getline(std::cin, line))
                {
                    std::cout << std::endl;
                    break;
                }
                line = trim(line);
                if (line.empty())
                {
                    continue;
                }
                logger_.log("cmd", line);

                const auto tokens = split_tokens(line);
                if (tokens.empty())
                {
                    continue;
                }
                const auto command = to_upper(tokens[0]);
                const std::vector<std::string> args(tokens.begin() + 1, tokens.end());

                if (command == "EXIT" || command == "QUIT")
                {
                    std::cout << "OK" << std::endl;
                    break;
                }
                if (command == "HELP")
                {
                    print_help();
                    continue;
                }

                try
                {
                    if (!dispatch(command, args))
                    {
                        std::cout << "ERROR: unsupported_command" << std::endl;
                    }
                }
                catch (const std::exception &ex)
                {
                    std::cout << "ERROR: internal_error" << std::endl;
                    std::cout << ex.what() << std::endl;
                    logger_.log("error", "command failed: ", ex.what());
                }
            }
        }

        void resume_pending_transfers()
        {
            auto pending = state_store_.pending_for_identity(identity_);
            if (pending.empty())
            {
                return;
            }
            if (!ask_yes_no("Incomplete upload/downloads detected, resume?"))
            {
                discard_pending_transfers(pending);
                return;
            }
            for (const auto &entry : pending)
            {
                const auto local_str = entry.local_path.generic_string();
                if (entry.type == "upload")
                {
                    std::cout << "> UPLOAD " << local_str << ' ' << entry.remote_path << std::endl;
                    perform_upload(entry.local_path, entry.remote_path, true);
                }
                else if (entry.type == "download")
                {
                    std::cout << "> DOWNLOAD " << entry.remote_path << ' ' << local_str << std::endl;
                    perform_download(entry.remote_path, entry.local_path, true);
                }
            }
        }

        bool dispatch(const std::string &command, const std::vector<std::string> &args)
        {
            if (command == "LIST")
            {
                return handle_list(args);
            }
            if (command == "CD")
            {
                return handle_cd(args);
            }
            if (command == "MKDIR")
            {
                return handle_simple_path_command(minidrive::protocol::Command::Mkdir, args, 1);
            }
            if (command == "RMDIR")
            {
                return handle_simple_path_command(minidrive::protocol::Command::Rmdir, args, 1);
            }
            if (command == "DELETE")
            {
                return handle_simple_path_command(minidrive::protocol::Command::Delete, args, 1);
            }
            if (command == "MOVE")
            {
                return handle_move_copy(minidrive::protocol::Command::Move, args);
            }
            if (command == "COPY")
            {
                return handle_move_copy(minidrive::protocol::Command::Copy, args);
            }
            if (command == "UPLOAD")
            {
                return handle_upload(args);
            }
            if (command == "DOWNLOAD")
            {
                return handle_download(args);
            }
            if (command == "SYNC")
            {
                return handle_sync(args);
            }
            if (command == "STAT")
            {
                return handle_stat(args);
            }
            return false;
        }

        void discard_pending_transfers(const std::vector<TransferStateStore::Entry> &entries)
        {
            for (const auto &entry : entries)
            {
                if (entry.type == "upload")
                {
                    state_store_.remove_upload(entry.identity, entry.local_path, entry.remote_path);
                }
                else if (entry.type == "download")
                {
                    remove_partial_download_artifacts(entry);
                    state_store_.remove_download(entry.identity, entry.local_path, entry.remote_path);
                }
            }
        }

        void remove_partial_download_artifacts(const TransferStateStore::Entry &entry)
        {
            auto part_path = entry.local_path;
            part_path += ".part";
            std::error_code ec;
            std::filesystem::remove(part_path, ec);
        }

        bool handle_list(const std::vector<std::string> &args)
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

        bool handle_stat(const std::vector<std::string> &args)
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
            std::cout << "Modified: " << metadata.modified_time << std::endl;
            if (metadata.content_hash)
            {
                std::cout << "Hash: " << *metadata.content_hash << std::endl;
            }
            return true;
        }

        bool handle_cd(const std::vector<std::string> &args)
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
                std::cout << "Target is not a directory." << std::endl;
                return true;
            }
            remote_cwd_ = normalize_remote(metadata.path);
            std::cout << "OK" << std::endl;
            return true;
        }

        bool handle_simple_path_command(minidrive::protocol::Command command, const std::vector<std::string> &args,
                                        std::size_t expected_args)
        {
            if (args.size() != expected_args)
            {
                std::cout << "ERROR: invalid_usage" << std::endl;
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
            if (!response.message.empty())
            {
                std::cout << response.message << std::endl;
            }
            return true;
        }

        bool handle_move_copy(minidrive::protocol::Command command, const std::vector<std::string> &args)
        {
            if (args.size() != 2)
            {
                std::cout << "ERROR: invalid_usage" << std::endl;
                std::cout << "Usage: " << (command == minidrive::protocol::Command::Move ? "MOVE" : "COPY")
                          << " <src> <dst>" << std::endl;
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

        bool handle_upload(const std::vector<std::string> &args)
        {
            if (args.empty() || args.size() > 2)
            {
                std::cout << "ERROR: invalid_usage" << std::endl;
                std::cout << "Usage: UPLOAD <local_path> [remote_path]" << std::endl;
                return true;
            }
            const std::filesystem::path local_path = std::filesystem::path(args[0]);
            std::string remote_target = args.size() == 2 ? args[1] : local_path.filename().generic_string();
            if (remote_target.empty())
            {
                remote_target = args[0];
            }
            remote_target = resolve_remote_path(remote_target);
            return perform_upload(local_path, remote_target, false);
        }

        bool handle_download(const std::vector<std::string> &args)
        {
            if (args.empty() || args.size() > 2)
            {
                std::cout << "ERROR: invalid_usage" << std::endl;
                std::cout << "Usage: DOWNLOAD <remote_path> [local_path]" << std::endl;
                return true;
            }
            const std::string remote_input = args[0];
            const std::string remote_path = resolve_remote_path(remote_input);
            std::filesystem::path local_target;
            if (args.size() == 2)
            {
                local_target = std::filesystem::path(args[1]);
            }
            else
            {
                local_target = std::filesystem::path(remote_input).filename();
                if (local_target.empty())
                {
                    local_target = std::filesystem::path("downloaded_file");
                }
            }
            return perform_download(remote_path, local_target, false);
        }

        bool perform_upload(const std::filesystem::path &local_path_input, const std::string &remote_target,
                            bool from_resume)
        {
            const auto absolute_local = std::filesystem::absolute(local_path_input);
            if (!std::filesystem::exists(absolute_local))
            {
                std::cout << "ERROR: file_not_found" << std::endl;
                std::cout << "Local file does not exist." << std::endl;
                state_store_.remove_upload(identity_, absolute_local, remote_target);
                return true;
            }
            if (!std::filesystem::is_regular_file(absolute_local))
            {
                std::cout << "ERROR: invalid_target" << std::endl;
                std::cout << "Local path is not a file." << std::endl;
                state_store_.remove_upload(identity_, absolute_local, remote_target);
                return true;
            }

            const auto file_size = std::filesystem::file_size(absolute_local);
            const auto root_hash = minidrive::crypto::hash_file(absolute_local);

            if (!from_resume)
            {
                state_store_.upsert_upload(identity_, absolute_local, remote_target, file_size);
            }

            if (!ensure_remote_parent_directory(remote_target))
            {
                return true;
            }

            constexpr std::uint64_t kChunkSize = 64 * 1024;
            minidrive::protocol::UploadInitRequest init{
                .remote_path = remote_target,
                .file_size = file_size,
                .chunk_size = kChunkSize,
                .root_hash = root_hash,
                .resume = true,
            };

            auto init_response = rpc(minidrive::protocol::Command::UploadInit, init);
            if (init_response.kind == minidrive::protocol::ResponseKind::Error)
            {
                print_error(init_response);
                return true;
            }

            const auto descriptor = init_response.payload.at("descriptor").get<minidrive::protocol::TransferDescriptor>();
            const auto bytes_written = init_response.payload.value("bytes_written", 0ULL);

            std::ifstream in(absolute_local, std::ios::binary);
            if (!in.is_open())
            {
                std::cout << "ERROR: file_io" << std::endl;
                std::cout << "Could not open local file for reading." << std::endl;
                return true;
            }

            if (bytes_written > 0)
            {
                in.seekg(static_cast<std::streamoff>(bytes_written));
                std::cout << "Resuming upload from byte " << bytes_written << std::endl;
            }
            state_store_.update_upload_progress(identity_, absolute_local, remote_target, bytes_written);

            std::vector<char> buffer(static_cast<std::size_t>(descriptor.chunk_size));
            std::uint64_t offset = bytes_written;
            bool aborted = false;

            while (in && offset < descriptor.total_size)
            {
                in.read(buffer.data(), static_cast<std::streamsize>(descriptor.chunk_size));
                const auto read_count = static_cast<std::size_t>(in.gcount());
                if (read_count == 0)
                {
                    break;
                }
                std::vector<std::byte> chunk(read_count);
                std::memcpy(chunk.data(), buffer.data(), read_count);
                const auto chunk_hash = minidrive::crypto::hash_bytes(chunk);
                const auto encoded = encode_base64(chunk);
                minidrive::protocol::UploadChunkRequest chunk_request{
                    .transfer_id = descriptor.transfer_id,
                    .offset = offset,
                    .data_base64 = encoded,
                    .chunk_hash = chunk_hash,
                };
                const auto send_start = std::chrono::steady_clock::now();
                auto chunk_response = rpc(minidrive::protocol::Command::UploadChunk, chunk_request);
                if (chunk_response.kind == minidrive::protocol::ResponseKind::Error)
                {
                    print_error(chunk_response);
                    aborted = true;
                    break;
                }
                apply_rate_limit(config_.max_upload_rate, read_count, send_start);
                offset += read_count;
                state_store_.update_upload_progress(identity_, absolute_local, remote_target, offset);
                std::cout << "\rUploaded " << offset << " / " << descriptor.total_size << " bytes" << std::flush;
            }
            std::cout << std::endl;

            if (aborted)
            {
                return true;
            }

            if (offset != descriptor.total_size)
            {
                std::cout << "ERROR: upload_incomplete" << std::endl;
                std::cout << "Upload interrupted before completion." << std::endl;
                return true;
            }

            minidrive::protocol::UploadCommitRequest commit{
                .transfer_id = descriptor.transfer_id,
                .final_hash = root_hash,
            };
            auto commit_response = rpc(minidrive::protocol::Command::UploadCommit, commit);
            if (commit_response.kind == minidrive::protocol::ResponseKind::Error)
            {
                print_error(commit_response);
                return true;
            }

            state_store_.remove_upload(identity_, absolute_local, remote_target);
            std::cout << "OK" << std::endl;
            return true;
        }

        bool perform_download(const std::string &remote_path, const std::filesystem::path &local_target_input,
                              bool from_resume)
        {
            const auto absolute_local = std::filesystem::absolute(local_target_input);
            if (std::filesystem::exists(absolute_local) && !from_resume)
            {
                std::cout << "ERROR: file_exists" << std::endl;
                std::cout << "Local file already exists." << std::endl;
                return true;
            }

            auto parent = absolute_local.parent_path();
            if (!parent.empty())
            {
                std::error_code ec;
                std::filesystem::create_directories(parent, ec);
            }

            auto part_path = absolute_local;
            part_path += ".part";
            std::uint64_t existing_bytes = 0;
            if (std::filesystem::exists(part_path))
            {
                existing_bytes = std::filesystem::file_size(part_path);
            }

            minidrive::protocol::DownloadInitRequest request{.remote_path = remote_path};
            auto init_response = rpc(minidrive::protocol::Command::DownloadInit, request);
            if (init_response.kind == minidrive::protocol::ResponseKind::Error)
            {
                print_error(init_response);
                return true;
            }

            const auto descriptor = init_response.payload.at("descriptor").get<minidrive::protocol::TransferDescriptor>();
            if (existing_bytes > descriptor.total_size)
            {
                std::cout << "ERROR: invalid_state" << std::endl;
                std::cout << "Local partial file is larger than remote file." << std::endl;
                return true;
            }

            if (!from_resume)
            {
                state_store_.upsert_download(identity_, absolute_local, remote_path, descriptor.total_size, existing_bytes);
            }
            else
            {
                state_store_.update_download_progress(identity_, absolute_local, remote_path, existing_bytes);
            }

            std::fstream part(part_path, std::ios::binary | std::ios::in | std::ios::out);
            if (!part.is_open())
            {
                part.open(part_path, std::ios::binary | std::ios::out | std::ios::trunc);
                part.close();
                part.open(part_path, std::ios::binary | std::ios::in | std::ios::out);
            }
            if (!part.is_open())
            {
                std::cout << "ERROR: file_io" << std::endl;
                std::cout << "Failed to open partial file for writing." << std::endl;
                return true;
            }

            std::uint64_t offset = existing_bytes;
            if (offset > 0)
            {
                std::cout << "Resuming download from byte " << offset << std::endl;
            }

            bool aborted = false;
            while (offset < descriptor.total_size)
            {
                minidrive::protocol::DownloadChunkRequest chunk_request{
                    .transfer_id = descriptor.transfer_id,
                    .offset = offset,
                    .max_bytes = descriptor.chunk_size,
                };
                const auto recv_start = std::chrono::steady_clock::now();
                auto chunk_response = rpc(minidrive::protocol::Command::DownloadChunk, chunk_request);
                if (chunk_response.kind == minidrive::protocol::ResponseKind::Error)
                {
                    print_error(chunk_response);
                    aborted = true;
                    break;
                }
                const auto payload = chunk_response.payload.get<minidrive::protocol::DownloadChunkResponse>();
                apply_rate_limit(config_.max_download_rate, static_cast<std::size_t>(payload.bytes), recv_start);
                if (payload.bytes == 0 && !payload.done)
                {
                    std::cout << "ERROR: invalid_response" << std::endl;
                    aborted = true;
                    break;
                }
                const auto data = decode_base64(payload.data_base64);
                if (data.size() != static_cast<std::size_t>(payload.bytes))
                {
                    std::cout << "ERROR: invalid_response" << std::endl;
                    aborted = true;
                    break;
                }
                const auto chunk_hash = minidrive::crypto::hash_bytes(data);
                if (!payload.chunk_hash.empty() && chunk_hash != payload.chunk_hash)
                {
                    std::cout << "ERROR: hash_mismatch" << std::endl;
                    std::cout << "Chunk hash verification failed." << std::endl;
                    aborted = true;
                    break;
                }
                part.seekp(static_cast<std::streamoff>(offset));
                part.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
                if (!part)
                {
                    std::cout << "ERROR: file_io" << std::endl;
                    std::cout << "Failed to write to partial file." << std::endl;
                    aborted = true;
                    break;
                }
                part.flush();
                offset += data.size();
                state_store_.update_download_progress(identity_, absolute_local, remote_path, offset);
                std::cout << "\rDownloaded " << offset << " / " << descriptor.total_size << " bytes" << std::flush;
                if (payload.done && offset >= descriptor.total_size)
                {
                    break;
                }
            }
            std::cout << std::endl;

            if (aborted)
            {
                return true;
            }

            if (offset != descriptor.total_size)
            {
                std::cout << "ERROR: download_incomplete" << std::endl;
                std::cout << "Download interrupted before completion." << std::endl;
                return true;
            }

            part.close();
            const auto file_hash = minidrive::crypto::hash_file(part_path);
            if (descriptor.root_hash && file_hash != *descriptor.root_hash)
            {
                std::cout << "ERROR: hash_mismatch" << std::endl;
                std::cout << "File hash verification failed." << std::endl;
                return true;
            }

            if (std::filesystem::exists(absolute_local))
            {
                std::cout << "ERROR: file_exists" << std::endl;
                std::cout << "Local file already exists." << std::endl;
                return true;
            }

            std::error_code ec;
            std::filesystem::rename(part_path, absolute_local, ec);
            if (ec)
            {
                std::cout << "ERROR: file_io" << std::endl;
                std::cout << "Failed to finalize downloaded file: " << ec.message() << std::endl;
                return true;
            }

            state_store_.remove_download(identity_, absolute_local, remote_path);
            std::cout << "OK" << std::endl;
            return true;
        }

        bool handle_sync(const std::vector<std::string> &args)
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

        std::map<std::string, SnapshotEntry> build_local_snapshot(const std::filesystem::path &root)
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

        std::map<std::string, SnapshotEntry> build_remote_snapshot(const std::string &remote_root)
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

        bool ensure_remote_directory(const std::string &remote_path)
        {
            minidrive::protocol::PathRequest request{.path = remote_path};
            auto response = rpc(minidrive::protocol::Command::Stat, request);
            if (response.kind == minidrive::protocol::ResponseKind::Ok)
            {
                const auto metadata = response.payload.at("metadata").get<minidrive::protocol::FileMetadata>();
                if (!metadata.is_directory)
                {
                    std::cout << "ERROR: invalid_target" << std::endl;
                    std::cout << "Remote path is not a directory." << std::endl;
                    return false;
                }
                return true;
            }
            if (response.error == minidrive::ErrorCode::NotFound)
            {
                auto create_response = rpc(minidrive::protocol::Command::Mkdir, request);
                if (create_response.kind == minidrive::protocol::ResponseKind::Error)
                {
                    print_error(create_response);
                    return false;
                }
                return true;
            }
            print_error(response);
            return false;
        }

        bool ensure_remote_parent_directory(const std::string &remote_path)
        {
            std::filesystem::path remote(remote_path);
            auto parent = remote.parent_path();
            if (parent.empty() || parent.generic_string() == ".")
            {
                return true;
            }
            return ensure_remote_directory(parent.generic_string());
        }

        std::string join_remote_path(const std::string &remote_root, const std::string &relative) const
        {
            if (relative.empty() || relative == ".")
            {
                return remote_root;
            }
            std::filesystem::path combined = std::filesystem::path(remote_root) / relative;
            return normalize_remote_for_join(combined.generic_string());
        }

        std::string normalize_remote_for_join(std::string path) const
        {
            std::filesystem::path p(path);
            p = p.lexically_normal();
            if (p.empty())
            {
                return ".";
            }
            return p.generic_string();
        }

        minidrive::protocol::ResponseEnvelope rpc(minidrive::protocol::Command command,
                                                  const nlohmann::json &payload = nlohmann::json::object())
        {
            minidrive::protocol::RequestEnvelope envelope;
            envelope.command = command;
            envelope.payload = payload;
            envelope.request_id = next_request_id();

            const auto frame = minidrive::protocol::encode_frame(nlohmann::json(envelope));
            asio::write(socket_, asio::buffer(frame));

            std::array<std::uint8_t, 4> header{};
            asio::read(socket_, asio::buffer(header));
            const auto size = (static_cast<std::uint32_t>(header[0]) << 24) | (static_cast<std::uint32_t>(header[1]) << 16) |
                              (static_cast<std::uint32_t>(header[2]) << 8) | static_cast<std::uint32_t>(header[3]);
            std::vector<char> buffer(size);
            asio::read(socket_, asio::buffer(buffer.data(), buffer.size()));

            nlohmann::json json_response;
            try
            {
                json_response = nlohmann::json::parse(std::string(buffer.begin(), buffer.end()));
            }
            catch (const std::exception &ex)
            {
                logger_.log("rpc", "parse_error size=", size, " msg=", ex.what());
                throw std::runtime_error("Failed to decode server response");
            }
            auto response = json_response.get<minidrive::protocol::ResponseEnvelope>();
            if (response.kind == minidrive::protocol::ResponseKind::Error)
            {
                logger_.log("rpc", "error=", minidrive::to_string(response.error), " msg=", response.message);
            }
            else
            {
                logger_.log("rpc", "success cmd=", static_cast<int>(command));
            }
            return response;
        }

        void print_help() const
        {
            std::cout << "Available commands:" << std::endl;
            std::cout << "  HELP                      Show this help" << std::endl;
            std::cout << "  EXIT                      Disconnect and exit" << std::endl;
            std::cout << "  LIST [path]               List directory contents" << std::endl;
            std::cout << "  STAT <path>               Show metadata for a path" << std::endl;
            std::cout << "  CD <path>                 Change current remote directory" << std::endl;
            std::cout << "  MKDIR <path>              Create a directory" << std::endl;
            std::cout << "  RMDIR <path>              Remove an empty directory" << std::endl;
            std::cout << "  MOVE <src> <dst>          Move or rename an entry" << std::endl;
            std::cout << "  COPY <src> <dst>          Copy an entry" << std::endl;
            std::cout << "  DELETE <path>             Delete a file" << std::endl;
            std::cout << "  UPLOAD <local> [remote]   Upload a file to the server" << std::endl;
            std::cout << "  DOWNLOAD <remote> [local] Download a file" << std::endl;
            std::cout << "  SYNC <local> <remote>     Synchronize local directory to remote" << std::endl;
            std::cout << "\nFlags:\n";
            std::cout << "  --log <file>              Append structured logs to file\n";
            std::cout << "  --max-upload-rate <bps>   Throttle uploads (bytes per second)\n";
            std::cout << "  --max-download-rate <bps> Throttle downloads (bytes per second)\n";
        }

        void print_error(const minidrive::protocol::ResponseEnvelope &response) const
        {
            std::cout << "ERROR: " << minidrive::to_string(response.error) << std::endl;
            if (!response.message.empty())
            {
                std::cout << response.message << std::endl;
            }
        }

        std::string resolve_remote_path(const std::string &input) const
        {
            if (input.empty())
            {
                return remote_cwd_;
            }
            std::filesystem::path path(input);
            if (path.is_relative())
            {
                path = std::filesystem::path(remote_cwd_) / path;
            }
            return normalize_remote(path.generic_string());
        }

        static std::string normalize_remote(std::string path)
        {
            std::filesystem::path p(path);
            p = p.lexically_normal();
            if (p.empty() || p == ".")
            {
                return ".";
            }
            return p.generic_string();
        }

        std::string identity_prompt() const
        {
            return identity_ + ":" + remote_cwd_;
        }

        std::string next_request_id()
        {
            std::ostringstream oss;
            oss << "req-" << (++request_counter_);
            return oss.str();
        }

        ClientConfig config_;
        Logger logger_;
        TransferStateStore state_store_;
        asio::io_context io_context_;
        asio::ip::tcp::socket socket_;
        std::string identity_;
        std::string remote_cwd_{"."};
        std::uint64_t request_counter_{0};
    };

} // namespace

int main(int argc, char *argv[])
{
    try
    {
        const auto config = parse_arguments(argc, argv);
        Logger logger(config.log_path);
        ClientSession session(config, std::move(logger));
        return session.run();
    }
    catch (const std::exception &ex)
    {
        std::cerr << "ERROR: " << ex.what() << std::endl;
        return 1;
    }
}
