#include <array>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "minidrive/crypto.hpp"
#include "minidrive/framing.hpp"
#include "minidrive/protocol.hpp"

using namespace minidrive;
using namespace minidrive::protocol;

void run_server_component_tests();

namespace
{

    void test_request_roundtrip()
    {
        ListRequest list_req{.path = "/documents"};
        RequestEnvelope envelope{};
        envelope.command = Command::List;
        envelope.payload = list_req;
        envelope.request_id = std::string("req-42");

        const auto json = nlohmann::json(envelope);
        const auto decoded = json.get<RequestEnvelope>();

        assert(decoded.command == Command::List);
        assert(decoded.payload == envelope.payload);
        assert(decoded.request_id == envelope.request_id);
    }

    void test_response_roundtrip()
    {
        SyncPlan plan{};
        plan.entries.push_back(SyncDiffEntry{
            .action = SyncAction::Upload,
            .metadata = FileMetadata{
                .path = "notes.txt",
                .size = 1024,
                .modified_time = 1700000000,
                .is_directory = false,
                .content_hash = std::string("abcd"),
            },
            .reason = std::string("new file"),
        });

        ResponseEnvelope envelope{};
        envelope.kind = ResponseKind::Ok;
        envelope.error = ErrorCode::Ok;
        envelope.message = "plan ready";
        envelope.payload = plan;

        const auto json = nlohmann::json(envelope);
        const auto decoded = json.get<ResponseEnvelope>();

        assert(decoded.kind == ResponseKind::Ok);
        assert(decoded.error == ErrorCode::Ok);
        assert(decoded.payload == envelope.payload);
    }

    void test_authentication_payload()
    {
        AuthenticateRequest request{
            .public_mode = false,
            .username = "alice",
            .password = "secret",
            .register_user = true,
        };

        const auto json = nlohmann::json(request);
        const auto decoded = json.get<AuthenticateRequest>();
        assert(decoded.public_mode == request.public_mode);
        assert(decoded.username == request.username);
        assert(decoded.register_user == request.register_user);

        AuthenticateResponse response{
            .success = true,
            .newly_registered = true,
            .identity = "alice",
        };

        const auto response_json = nlohmann::json(response);
        const auto decoded_response = response_json.get<AuthenticateResponse>();
        assert(decoded_response.success == response.success);
        assert(decoded_response.identity == response.identity);
    }

    void test_sync_serialization()
    {
        FileMetadata metadata{
            .path = "folder/image.png",
            .size = 42,
            .modified_time = 123456,
            .is_directory = false,
            .content_hash = std::string("cafebabe"),
        };

        const auto metadata_json = nlohmann::json(metadata);
        const auto decoded_metadata = metadata_json.get<FileMetadata>();
        assert(decoded_metadata.path == metadata.path);
        assert(decoded_metadata.content_hash == metadata.content_hash);

        SyncDiffEntry entry{
            .action = SyncAction::DeleteRemote,
            .metadata = metadata,
            .reason = std::string("removed locally"),
        };

        const auto entry_json = nlohmann::json(entry);
        const auto decoded_entry = entry_json.get<SyncDiffEntry>();
        assert(decoded_entry.action == SyncAction::DeleteRemote);
        assert(decoded_entry.reason == entry.reason);

        SyncPlan plan{};
        plan.entries.push_back(entry);
        plan.entries.push_back(SyncDiffEntry{
            .action = SyncAction::Skip,
            .metadata = FileMetadata{.path = "unchanged", .is_directory = true},
            .reason = std::nullopt,
        });

        const auto plan_json = nlohmann::json(plan);
        const auto decoded_plan = plan_json.get<SyncPlan>();
        assert(decoded_plan.entries.size() == plan.entries.size());
        assert(decoded_plan.entries[1].metadata.path == "unchanged");
    }

    void test_framing()
    {
        UploadInitRequest init{
            .remote_path = "notes.txt",
            .file_size = 4096,
            .chunk_size = 1024,
            .root_hash = "deadbeef",
            .resume = true,
        };

        RequestEnvelope envelope{};
        envelope.command = Command::UploadInit;
        envelope.payload = init;

        const auto json = nlohmann::json(envelope);
        const auto frame = encode_frame(json);
        const auto decoded = try_decode_frame(std::span<const std::uint8_t>(frame.data(), frame.size()));
        assert(decoded.has_value());
        assert(decoded->bytes_consumed == frame.size());
        const auto decoded_envelope = decoded->message.get<RequestEnvelope>();
        assert(decoded_envelope.command == Command::UploadInit);
        assert(decoded_envelope.payload == envelope.payload);
    }

    void test_upload_chunk_roundtrip()
    {
        UploadChunkRequest chunk{
            .transfer_id = "t-1",
            .offset = 2048,
            .data_base64 = "ZGF0YQ==",
            .chunk_hash = "abcd",
        };

        const auto json = nlohmann::json(chunk);
        const auto decoded = json.get<UploadChunkRequest>();
        assert(decoded.transfer_id == chunk.transfer_id);
        assert(decoded.offset == chunk.offset);
        assert(decoded.data_base64 == chunk.data_base64);
        assert(decoded.chunk_hash == chunk.chunk_hash);
    }

    void test_download_response_roundtrip()
    {
        DownloadInitResponse response{
            .descriptor = TransferDescriptor{
                .transfer_id = "t-2",
                .total_size = 4096,
                .chunk_size = 512,
                .root_hash = std::string("hash"),
            },
            .metadata = FileMetadata{
                .path = "remote.bin",
                .size = 4096,
                .modified_time = 111,
                .is_directory = false,
                .content_hash = std::string("hash"),
            },
        };

        const auto json = nlohmann::json(response);
        const auto decoded = json.get<DownloadInitResponse>();
        assert(decoded.descriptor.transfer_id == response.descriptor.transfer_id);
        assert(decoded.metadata.path == response.metadata.path);
        assert(decoded.metadata.is_directory == response.metadata.is_directory);
    }

    void test_download_chunk_roundtrip()
    {
        DownloadChunkRequest request{
            .transfer_id = "t-3",
            .offset = 1024,
            .max_bytes = 512,
        };

        const auto request_json = nlohmann::json(request);
        const auto decoded_request = request_json.get<DownloadChunkRequest>();
        assert(decoded_request.transfer_id == request.transfer_id);
        assert(decoded_request.offset == request.offset);
        assert(decoded_request.max_bytes == request.max_bytes);

        DownloadChunkResponse response{
            .transfer_id = request.transfer_id,
            .offset = request.offset,
            .bytes = 512,
            .done = false,
            .data_base64 = "dGVzdA==",
            .chunk_hash = "1234",
        };

        const auto response_json = nlohmann::json(response);
        const auto decoded_response = response_json.get<DownloadChunkResponse>();
        assert(decoded_response.transfer_id == response.transfer_id);
        assert(decoded_response.bytes == response.bytes);
        assert(decoded_response.data_base64 == response.data_base64);
    }

    void test_crypto()
    {
        const std::string password = "correct horse battery staple";
        const auto hashed = crypto::hash_password(password);
        assert(crypto::verify_password(password, hashed));
        assert(!crypto::verify_password("wrong password", hashed));

        const std::array<std::byte, 4> chunk = {
            std::byte{0xDE},
            std::byte{0xAD},
            std::byte{0xBE},
            std::byte{0xEF},
        };
        const auto chunk_hash = crypto::hash_bytes(chunk);

        std::istringstream stream(std::string("\xDE\xAD\xBE\xEF", 4));
        const auto stream_hash = crypto::hash_stream(stream);
        assert(chunk_hash == stream_hash);

        const auto temp_dir = std::filesystem::temp_directory_path();
        const auto file_path = temp_dir / "minidrive_crypto_test.bin";
        {
            std::ofstream file(file_path, std::ios::binary);
            file.write("\xDE\xAD\xBE\xEF", 4);
        }
        const auto file_hash = crypto::hash_file(file_path);
        assert(file_hash == chunk_hash);
        std::filesystem::remove(file_path);
    }

} // namespace

int main()
{
    try
    {
        test_request_roundtrip();
        test_response_roundtrip();
        test_authentication_payload();
        test_sync_serialization();
        test_framing();
        test_upload_chunk_roundtrip();
        test_download_response_roundtrip();
        test_download_chunk_roundtrip();
        test_crypto();
        run_server_component_tests();
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Test failure: " << ex.what() << '\n';
        return 1;
    }
    return 0;
}
