#include "minidrive/client/session.hpp"

#include <asio/connect.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include "minidrive/encoding/base64.hpp"
#include "minidrive/error_codes.hpp"
#include "minidrive/framing.hpp"
#include "minidrive/protocol.hpp"

namespace minidrive::client
{

    namespace
    {

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

    } // namespace

    ClientSession::ClientSession(ClientConfig config, Logger logger)
        : config_(std::move(config)),
          logger_(std::move(logger)),
          state_store_(),
          socket_(io_context_) {}

    int ClientSession::run()
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

    void ClientSession::connect()
    {
        asio::ip::tcp::resolver resolver(io_context_);
        const auto results = resolver.resolve(config_.host, std::to_string(config_.port));
        asio::connect(socket_, results);
        logger_.log("info", "connected to ", config_.host, ':', config_.port);
    }

    std::string ClientSession::prompt_password(const std::string &username)
    {
        std::string password;
        std::cout << "Password for " << username << ": " << std::flush;
        std::getline(std::cin, password);
        return password;
    }

    bool ClientSession::ask_yes_no(const std::string &question) const
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

    void ClientSession::authenticate()
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

    void ClientSession::interactive_shell()
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

    void ClientSession::resume_pending_transfers()
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

    bool ClientSession::dispatch(const std::string &command, const std::vector<std::string> &args)
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

    void ClientSession::discard_pending_transfers(const std::vector<TransferStateStore::Entry> &entries)
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

    void ClientSession::remove_partial_download_artifacts(const TransferStateStore::Entry &entry)
    {
        auto part_path = entry.local_path;
        part_path += ".part";
        std::error_code ec;
        std::filesystem::remove(part_path, ec);
    }

    void ClientSession::print_help() const
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

    void ClientSession::print_error(const minidrive::protocol::ResponseEnvelope &response) const
    {
        std::cout << "ERROR: " << minidrive::to_string(response.error) << std::endl;
        if (!response.message.empty())
        {
            std::cout << response.message << std::endl;
        }
    }

    std::string ClientSession::resolve_remote_path(const std::string &input) const
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

    std::string ClientSession::normalize_remote(std::string path)
    {
        std::filesystem::path p(path);
        p = p.lexically_normal();
        if (p.empty() || p == ".")
        {
            return ".";
        }
        return p.generic_string();
    }

    std::string ClientSession::join_remote_path(const std::string &remote_root, const std::string &relative) const
    {
        if (relative.empty() || relative == ".")
        {
            return remote_root;
        }
        std::filesystem::path combined = std::filesystem::path(remote_root) / relative;
        return normalize_remote_for_join(combined.generic_string());
    }

    std::string ClientSession::normalize_remote_for_join(std::string path) const
    {
        std::filesystem::path p(path);
        p = p.lexically_normal();
        if (p.empty())
        {
            return ".";
        }
        return p.generic_string();
    }

    minidrive::protocol::ResponseEnvelope ClientSession::rpc(minidrive::protocol::Command command,
                                                             const nlohmann::json &payload)
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

    std::string ClientSession::identity_prompt() const
    {
        return identity_ + ":" + remote_cwd_;
    }

    std::string ClientSession::next_request_id()
    {
        std::ostringstream oss;
        oss << "req-" << (++request_counter_);
        return oss.str();
    }

} // namespace minidrive::client
