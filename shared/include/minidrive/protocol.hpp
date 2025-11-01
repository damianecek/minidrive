/**
 * MiniDrive - Shared protocol schema and serialization helpers.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "minidrive/error_codes.hpp"

namespace minidrive::protocol
{

    enum class Command : std::uint8_t
    {
        Authenticate,
        List,
        Stat,
        Mkdir,
        Rmdir,
        Move,
        Copy,
        Delete,
        UploadInit,
        UploadChunk,
        UploadCommit,
        DownloadInit,
        DownloadChunk,
        SyncEnumerate,
        SyncApply,
        ResumeTransfer,
        Ping
    };

    std::string_view to_string(Command command) noexcept;
    std::optional<Command> command_from_string(std::string_view value) noexcept;

    enum class ResponseKind : std::uint8_t
    {
        Ok = 0,
        Error = 1,
        Continue = 2
    };

    std::string_view to_string(ResponseKind kind) noexcept;
    std::optional<ResponseKind> response_kind_from_string(std::string_view value) noexcept;

    struct RequestEnvelope
    {
        Command command{};
        nlohmann::json payload{nlohmann::json::object()};
        std::optional<std::string> request_id{};
    };

    void to_json(nlohmann::json &json, const RequestEnvelope &envelope);
    void from_json(const nlohmann::json &json, RequestEnvelope &envelope);

    struct ResponseEnvelope
    {
        ResponseKind kind{ResponseKind::Ok};
        ErrorCode error{ErrorCode::Ok};
        std::string message{};
        nlohmann::json payload{nlohmann::json::object()};
        std::optional<std::string> request_id{};
    };

    void to_json(nlohmann::json &json, const ResponseEnvelope &envelope);
    void from_json(const nlohmann::json &json, ResponseEnvelope &envelope);

    struct AuthenticateRequest
    {
        bool public_mode{};
        std::string username{};
        std::string password{};
        bool register_user{};
    };

    void to_json(nlohmann::json &json, const AuthenticateRequest &request);
    void from_json(const nlohmann::json &json, AuthenticateRequest &request);

    struct AuthenticateResponse
    {
        bool success{};
        bool newly_registered{};
        std::string identity{};
    };

    void to_json(nlohmann::json &json, const AuthenticateResponse &response);
    void from_json(const nlohmann::json &json, AuthenticateResponse &response);

    struct FileMetadata
    {
        std::string path;
        std::uint64_t size{};
        std::uint64_t modified_time{};
        bool is_directory{};
        std::optional<std::string> content_hash{};
    };

    void to_json(nlohmann::json &json, const FileMetadata &metadata);
    void from_json(const nlohmann::json &json, FileMetadata &metadata);

    enum class SyncAction : std::uint8_t
    {
        Upload,
        Download,
        DeleteRemote,
        DeleteLocal,
        Conflict,
        Skip
    };

    std::string_view to_string(SyncAction action) noexcept;
    std::optional<SyncAction> sync_action_from_string(std::string_view value) noexcept;

    struct SyncDiffEntry
    {
        SyncAction action{SyncAction::Skip};
        FileMetadata metadata{};
        std::optional<std::string> reason{};
    };

    void to_json(nlohmann::json &json, const SyncDiffEntry &entry);
    void from_json(const nlohmann::json &json, SyncDiffEntry &entry);

    struct SyncPlan
    {
        std::vector<SyncDiffEntry> entries;
    };

    void to_json(nlohmann::json &json, const SyncPlan &plan);
    void from_json(const nlohmann::json &json, SyncPlan &plan);

    struct ListRequest
    {
        std::string path;
    };

    void to_json(nlohmann::json &json, const ListRequest &request);
    void from_json(const nlohmann::json &json, ListRequest &request);

    struct PathRequest
    {
        std::string path;
    };

    void to_json(nlohmann::json &json, const PathRequest &request);
    void from_json(const nlohmann::json &json, PathRequest &request);

    struct MoveCopyRequest
    {
        std::string source;
        std::string destination;
    };

    void to_json(nlohmann::json &json, const MoveCopyRequest &request);
    void from_json(const nlohmann::json &json, MoveCopyRequest &request);

    struct UploadInitRequest
    {
        std::string remote_path;
        std::uint64_t file_size{};
        std::uint64_t chunk_size{};
        std::string root_hash;
        bool resume{};
    };

    void to_json(nlohmann::json &json, const UploadInitRequest &request);
    void from_json(const nlohmann::json &json, UploadInitRequest &request);

    struct UploadChunkRequest
    {
        std::string transfer_id;
        std::uint64_t offset{};
        std::string data_base64;
        std::string chunk_hash;
    };

    void to_json(nlohmann::json &json, const UploadChunkRequest &request);
    void from_json(const nlohmann::json &json, UploadChunkRequest &request);

    struct UploadCommitRequest
    {
        std::string transfer_id;
        std::string final_hash;
    };

    void to_json(nlohmann::json &json, const UploadCommitRequest &request);
    void from_json(const nlohmann::json &json, UploadCommitRequest &request);

    struct DownloadInitRequest
    {
        std::string remote_path;
    };

    void to_json(nlohmann::json &json, const DownloadInitRequest &request);
    void from_json(const nlohmann::json &json, DownloadInitRequest &request);

    struct TransferDescriptor
    {
        std::string transfer_id;
        std::uint64_t total_size{};
        std::uint64_t chunk_size{};
        std::optional<std::string> root_hash{};
    };

    void to_json(nlohmann::json &json, const TransferDescriptor &descriptor);
    void from_json(const nlohmann::json &json, TransferDescriptor &descriptor);

    struct DownloadInitResponse
    {
        TransferDescriptor descriptor;
        FileMetadata metadata;
    };

    void to_json(nlohmann::json &json, const DownloadInitResponse &response);
    void from_json(const nlohmann::json &json, DownloadInitResponse &response);

    struct DownloadChunkRequest
    {
        std::string transfer_id;
        std::uint64_t offset{};
        std::uint64_t max_bytes{};
    };

    void to_json(nlohmann::json &json, const DownloadChunkRequest &request);
    void from_json(const nlohmann::json &json, DownloadChunkRequest &request);

    struct DownloadChunkResponse
    {
        std::string transfer_id;
        std::uint64_t offset{};
        std::uint64_t bytes{};
        bool done{};
        std::string data_base64;
        std::string chunk_hash;
    };

    void to_json(nlohmann::json &json, const DownloadChunkResponse &response);
    void from_json(const nlohmann::json &json, DownloadChunkResponse &response);

} // namespace minidrive::protocol
