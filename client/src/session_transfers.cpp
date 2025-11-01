#include "minidrive/client/session.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <thread>
#include <vector>

#include "minidrive/crypto.hpp"
#include "minidrive/encoding/base64.hpp"
#include "minidrive/error_codes.hpp"
#include "minidrive/protocol.hpp"

namespace minidrive::client
{

    namespace
    {

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

    } // namespace

    bool ClientSession::handle_upload(const std::vector<std::string> &args)
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

    bool ClientSession::handle_download(const std::vector<std::string> &args)
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

    bool ClientSession::perform_upload(const std::filesystem::path &local_path_input, const std::string &remote_target,
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
            in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const auto read_count = static_cast<std::size_t>(in.gcount());
            if (read_count == 0)
            {
                break;
            }
            minidrive::protocol::UploadChunkRequest chunk{
                .transfer_id = descriptor.transfer_id,
                .offset = offset,
                .data_base64 = minidrive::encoding::encode_base64(
                    std::as_bytes(std::span(buffer.data(), read_count))),
                .chunk_hash = minidrive::crypto::hash_bytes(std::as_bytes(std::span(buffer.data(), read_count))),
            };
            const auto send_start = std::chrono::steady_clock::now();
            auto chunk_response = rpc(minidrive::protocol::Command::UploadChunk, chunk);
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

    bool ClientSession::perform_download(const std::string &remote_path, const std::filesystem::path &local_target_input,
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
            const auto data = minidrive::encoding::decode_base64(payload.data_base64);
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

    bool ClientSession::ensure_remote_directory(const std::string &remote_path)
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

    bool ClientSession::ensure_remote_parent_directory(const std::string &remote_path)
    {
        std::filesystem::path remote(remote_path);
        auto parent = remote.parent_path();
        if (parent.empty() || parent.generic_string() == ".")
        {
            return true;
        }
        return ensure_remote_directory(parent.generic_string());
    }

} // namespace minidrive::client
