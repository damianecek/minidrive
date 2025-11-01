#include "minidrive/server/session.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <vector>

#include "minidrive/crypto.hpp"
#include "minidrive/encoding/base64.hpp"
#include "session_common.hpp"

namespace minidrive::server
{

    void Session::handle_download_init(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::DownloadInitRequest>();
            const auto path = services_.filesystem.resolve(session_paths_, request.remote_path);
            if (std::filesystem::is_directory(path))
            {
                send_error(minidrive::ErrorCode::Unsupported, "Cannot download a directory", envelope.request_id);
                return;
            }
            const auto file_size = std::filesystem::file_size(path);
            constexpr std::uint64_t kDefaultChunk = 1 << 20; // 1 MiB
            const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            const auto file_hash = crypto::hash_file(path);
            auto descriptor = minidrive::protocol::TransferDescriptor{
                .transfer_id = "download-" + std::to_string(now),
                .total_size = file_size,
                .chunk_size = kDefaultChunk,
                .root_hash = file_hash,
            };
            downloads_[descriptor.transfer_id] = DownloadTransfer{
                .path = path,
                .total_size = file_size,
                .chunk_size = descriptor.chunk_size,
                .root_hash = descriptor.root_hash.value_or(""),
            };

            nlohmann::json payload;
            payload["descriptor"] = descriptor;
            send_response(session_common::make_ok_response(payload, envelope.request_id));
        }
        catch (const FilesystemError &fs)
        {
            send_error(fs.code(), fs.what(), envelope.request_id);
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_download_chunk(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::DownloadChunkRequest>();
            auto it = downloads_.find(request.transfer_id);
            if (it == downloads_.end())
            {
                send_error(minidrive::ErrorCode::InvalidPayload, "Unknown transfer", envelope.request_id);
                return;
            }
            auto &transfer = it->second;
            if (request.offset > transfer.total_size)
            {
                send_error(minidrive::ErrorCode::InvalidPayload, "Invalid offset", envelope.request_id);
                return;
            }

            std::ifstream file(transfer.path, std::ios::binary);
            if (!file.is_open())
            {
                send_error(minidrive::ErrorCode::InternalError, "Failed to open file", envelope.request_id);
                downloads_.erase(it);
                return;
            }
            file.seekg(static_cast<std::streamoff>(request.offset));
            const auto max_bytes = std::min<std::uint64_t>(transfer.chunk_size, request.max_bytes);
            std::vector<std::byte> buffer(static_cast<std::size_t>(max_bytes));
            file.read(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
            const auto read_bytes = static_cast<std::size_t>(file.gcount());
            buffer.resize(read_bytes);
            const auto encoded = minidrive::encoding::encode_base64(buffer);

            const bool done = (request.offset + read_bytes) >= transfer.total_size;
            minidrive::protocol::DownloadChunkResponse chunk{
                .transfer_id = request.transfer_id,
                .offset = request.offset,
                .bytes = static_cast<std::uint64_t>(read_bytes),
                .done = done,
                .data_base64 = encoded,
                .chunk_hash = minidrive::crypto::hash_bytes(buffer),
            };
            nlohmann::json payload;
            payload = chunk;
            send_response(session_common::make_ok_response(payload, envelope.request_id));

            if (done)
            {
                downloads_.erase(it);
            }
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

} // namespace minidrive::server
