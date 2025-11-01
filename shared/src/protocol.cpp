#include "minidrive/protocol.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace minidrive::protocol
{

    namespace
    {

        struct CommandMapping
        {
            Command command;
            std::string_view label;
        };

        constexpr std::array<CommandMapping, 17> kCommandMappings{{
            {Command::Authenticate, "AUTHENTICATE"},
            {Command::List, "LIST"},
            {Command::Stat, "STAT"},
            {Command::Mkdir, "MKDIR"},
            {Command::Rmdir, "RMDIR"},
            {Command::Move, "MOVE"},
            {Command::Copy, "COPY"},
            {Command::Delete, "DELETE"},
            {Command::UploadInit, "UPLOAD_INIT"},
            {Command::UploadChunk, "UPLOAD_CHUNK"},
            {Command::UploadCommit, "UPLOAD_COMMIT"},
            {Command::DownloadInit, "DOWNLOAD_INIT"},
            {Command::DownloadChunk, "DOWNLOAD_CHUNK"},
            {Command::SyncEnumerate, "SYNC_ENUMERATE"},
            {Command::SyncApply, "SYNC_APPLY"},
            {Command::ResumeTransfer, "RESUME_TRANSFER"},
            {Command::Ping, "PING"},
        }};

        struct ResponseKindMapping
        {
            ResponseKind kind;
            std::string_view label;
        };

        constexpr std::array<ResponseKindMapping, 3> kResponseMappings{{
            {ResponseKind::Ok, "OK"},
            {ResponseKind::Error, "ERROR"},
            {ResponseKind::Continue, "CONTINUE"},
        }};

        struct SyncActionMapping
        {
            SyncAction action;
            std::string_view label;
        };

        constexpr std::array<SyncActionMapping, 6> kSyncActionMappings{{
            {SyncAction::Upload, "UPLOAD"},
            {SyncAction::Download, "DOWNLOAD"},
            {SyncAction::DeleteRemote, "DELETE_REMOTE"},
            {SyncAction::DeleteLocal, "DELETE_LOCAL"},
            {SyncAction::Conflict, "CONFLICT"},
            {SyncAction::Skip, "SKIP"},
        }};
    } // namespace

    std::string_view to_string(Command command) noexcept
    {
        for (const auto &mapping : kCommandMappings)
        {
            if (mapping.command == command)
            {
                return mapping.label;
            }
        }
        return "UNKNOWN";
    }

    std::optional<Command> command_from_string(std::string_view value) noexcept
    {
        for (const auto &mapping : kCommandMappings)
        {
            if (mapping.label == value)
            {
                return mapping.command;
            }
        }
        return std::nullopt;
    }

    std::string_view to_string(ResponseKind kind) noexcept
    {
        for (const auto &mapping : kResponseMappings)
        {
            if (mapping.kind == kind)
            {
                return mapping.label;
            }
        }
        return "UNKNOWN";
    }

    std::optional<ResponseKind> response_kind_from_string(std::string_view value) noexcept
    {
        for (const auto &mapping : kResponseMappings)
        {
            if (mapping.label == value)
            {
                return mapping.kind;
            }
        }
        return std::nullopt;
    }

    void to_json(nlohmann::json &json, const RequestEnvelope &envelope)
    {
        json = {
            {"cmd", to_string(envelope.command)},
            {"payload", envelope.payload},
        };
        if (envelope.request_id)
        {
            json["id"] = *envelope.request_id;
        }
    }

    void from_json(const nlohmann::json &json, RequestEnvelope &envelope)
    {
        const auto cmd_label = json.at("cmd").get<std::string>();
        auto cmd = command_from_string(cmd_label);
        if (!cmd)
        {
            throw std::runtime_error("Unknown command: " + cmd_label);
        }
        envelope.command = *cmd;
        envelope.payload = json.value("payload", nlohmann::json::object());
        if (auto it = json.find("id"); it != json.end())
        {
            envelope.request_id = it->get<std::string>();
        }
        else
        {
            envelope.request_id.reset();
        }
    }

    void to_json(nlohmann::json &json, const ResponseEnvelope &envelope)
    {
        json = {
            {"status", to_string(envelope.kind)},
            {"error", to_int(envelope.error)},
            {"message", envelope.message},
            {"payload", envelope.payload},
        };
        if (envelope.request_id)
        {
            json["id"] = *envelope.request_id;
        }
    }

    void from_json(const nlohmann::json &json, ResponseEnvelope &envelope)
    {
        const auto status_label = json.at("status").get<std::string>();
        auto kind = response_kind_from_string(status_label);
        if (!kind)
        {
            throw std::runtime_error("Unknown response status: " + status_label);
        }
        envelope.kind = *kind;
        const auto error_value = json.value("error", 0u);
        envelope.error = error_code_from_int(static_cast<std::uint16_t>(error_value));
        envelope.message = json.value("message", std::string{});
        envelope.payload = json.value("payload", nlohmann::json::object());
        if (auto it = json.find("id"); it != json.end())
        {
            envelope.request_id = it->get<std::string>();
        }
        else
        {
            envelope.request_id.reset();
        }
    }

    void to_json(nlohmann::json &json, const AuthenticateRequest &request)
    {
        json = {
            {"public", request.public_mode},
            {"username", request.username},
            {"password", request.password},
            {"register", request.register_user},
        };
    }

    void from_json(const nlohmann::json &json, AuthenticateRequest &request)
    {
        request.public_mode = json.value("public", false);
        request.username = json.value("username", std::string{});
        request.password = json.value("password", std::string{});
        request.register_user = json.value("register", false);
    }

    void to_json(nlohmann::json &json, const AuthenticateResponse &response)
    {
        json = {
            {"success", response.success},
            {"newly_registered", response.newly_registered},
            {"identity", response.identity},
        };
    }

    void from_json(const nlohmann::json &json, AuthenticateResponse &response)
    {
        response.success = json.value("success", false);
        response.newly_registered = json.value("newly_registered", false);
        response.identity = json.value("identity", std::string{});
    }

    void to_json(nlohmann::json &json, const FileMetadata &metadata)
    {
        json = {
            {"path", metadata.path},
            {"size", metadata.size},
            {"mtime", metadata.modified_time},
            {"is_dir", metadata.is_directory},
        };
        if (metadata.content_hash)
        {
            json["hash"] = *metadata.content_hash;
        }
    }

    void from_json(const nlohmann::json &json, FileMetadata &metadata)
    {
        metadata.path = json.at("path").get<std::string>();
        metadata.size = json.value("size", 0ULL);
        metadata.modified_time = json.value("mtime", 0ULL);
        metadata.is_directory = json.value("is_dir", false);
        if (auto it = json.find("hash"); it != json.end())
        {
            metadata.content_hash = it->get<std::string>();
        }
        else
        {
            metadata.content_hash.reset();
        }
    }

    std::string_view to_string(SyncAction action) noexcept
    {
        for (const auto &mapping : kSyncActionMappings)
        {
            if (mapping.action == action)
            {
                return mapping.label;
            }
        }
        return "UNKNOWN";
    }

    std::optional<SyncAction> sync_action_from_string(std::string_view value) noexcept
    {
        for (const auto &mapping : kSyncActionMappings)
        {
            if (mapping.label == value)
            {
                return mapping.action;
            }
        }
        return std::nullopt;
    }

    void to_json(nlohmann::json &json, const SyncDiffEntry &entry)
    {
        json = {
            {"action", to_string(entry.action)},
            {"metadata", entry.metadata},
        };
        if (entry.reason)
        {
            json["reason"] = *entry.reason;
        }
    }

    void from_json(const nlohmann::json &json, SyncDiffEntry &entry)
    {
        const auto action_label = json.at("action").get<std::string>();
        auto action = sync_action_from_string(action_label);
        if (!action)
        {
            throw std::runtime_error("Unknown sync action: " + action_label);
        }
        entry.action = *action;
        entry.metadata = json.at("metadata").get<FileMetadata>();
        if (auto it = json.find("reason"); it != json.end())
        {
            entry.reason = it->get<std::string>();
        }
        else
        {
            entry.reason.reset();
        }
    }

    void to_json(nlohmann::json &json, const SyncPlan &plan)
    {
        json = {{"entries", plan.entries}};
    }

    void from_json(const nlohmann::json &json, SyncPlan &plan)
    {
        plan.entries = json.value("entries", std::vector<SyncDiffEntry>{});
    }

    void to_json(nlohmann::json &json, const ListRequest &request)
    {
        json = {{"path", request.path}};
    }

    void from_json(const nlohmann::json &json, ListRequest &request)
    {
        request.path = json.at("path").get<std::string>();
    }

    void to_json(nlohmann::json &json, const PathRequest &request)
    {
        json = {{"path", request.path}};
    }

    void from_json(const nlohmann::json &json, PathRequest &request)
    {
        request.path = json.at("path").get<std::string>();
    }

    void to_json(nlohmann::json &json, const MoveCopyRequest &request)
    {
        json = {
            {"source", request.source},
            {"destination", request.destination},
        };
    }

    void from_json(const nlohmann::json &json, MoveCopyRequest &request)
    {
        request.source = json.at("source").get<std::string>();
        request.destination = json.at("destination").get<std::string>();
    }

    void to_json(nlohmann::json &json, const UploadInitRequest &request)
    {
        json = {
            {"remote_path", request.remote_path},
            {"file_size", request.file_size},
            {"chunk_size", request.chunk_size},
            {"root_hash", request.root_hash},
            {"resume", request.resume},
        };
    }

    void from_json(const nlohmann::json &json, UploadInitRequest &request)
    {
        request.remote_path = json.at("remote_path").get<std::string>();
        request.file_size = json.value("file_size", 0ULL);
        request.chunk_size = json.value("chunk_size", 0ULL);
        request.root_hash = json.value("root_hash", std::string{});
        request.resume = json.value("resume", false);
    }

    void to_json(nlohmann::json &json, const UploadChunkRequest &request)
    {
        json = {
            {"transfer_id", request.transfer_id},
            {"offset", request.offset},
            {"data", request.data_base64},
            {"hash", request.chunk_hash},
        };
    }

    void from_json(const nlohmann::json &json, UploadChunkRequest &request)
    {
        request.transfer_id = json.at("transfer_id").get<std::string>();
        request.offset = json.value("offset", 0ULL);
        request.data_base64 = json.value("data", std::string{});
        request.chunk_hash = json.value("hash", std::string{});
    }

    void to_json(nlohmann::json &json, const UploadCommitRequest &request)
    {
        json = {
            {"transfer_id", request.transfer_id},
            {"final_hash", request.final_hash},
        };
    }

    void from_json(const nlohmann::json &json, UploadCommitRequest &request)
    {
        request.transfer_id = json.at("transfer_id").get<std::string>();
        request.final_hash = json.at("final_hash").get<std::string>();
    }

    void to_json(nlohmann::json &json, const DownloadInitRequest &request)
    {
        json = {{"remote_path", request.remote_path}};
    }

    void from_json(const nlohmann::json &json, DownloadInitRequest &request)
    {
        request.remote_path = json.at("remote_path").get<std::string>();
    }

    void to_json(nlohmann::json &json, const TransferDescriptor &descriptor)
    {
        json = {
            {"transfer_id", descriptor.transfer_id},
            {"total_size", descriptor.total_size},
            {"chunk_size", descriptor.chunk_size},
        };
        if (descriptor.root_hash)
        {
            json["root_hash"] = *descriptor.root_hash;
        }
    }

    void from_json(const nlohmann::json &json, TransferDescriptor &descriptor)
    {
        descriptor.transfer_id = json.at("transfer_id").get<std::string>();
        descriptor.total_size = json.value("total_size", 0ULL);
        descriptor.chunk_size = json.value("chunk_size", 0ULL);
        if (auto it = json.find("root_hash"); it != json.end())
        {
            descriptor.root_hash = it->get<std::string>();
        }
        else
        {
            descriptor.root_hash.reset();
        }
    }

    void to_json(nlohmann::json &json, const DownloadInitResponse &response)
    {
        json = {
            {"descriptor", response.descriptor},
            {"metadata", response.metadata},
        };
    }

    void from_json(const nlohmann::json &json, DownloadInitResponse &response)
    {
        response.descriptor = json.at("descriptor").get<TransferDescriptor>();
        response.metadata = json.at("metadata").get<FileMetadata>();
    }

    void to_json(nlohmann::json &json, const DownloadChunkRequest &request)
    {
        json = {
            {"transfer_id", request.transfer_id},
            {"offset", request.offset},
            {"max_bytes", request.max_bytes},
        };
    }

    void from_json(const nlohmann::json &json, DownloadChunkRequest &request)
    {
        request.transfer_id = json.at("transfer_id").get<std::string>();
        request.offset = json.value("offset", 0ULL);
        request.max_bytes = json.value("max_bytes", 0ULL);
    }

    void to_json(nlohmann::json &json, const DownloadChunkResponse &response)
    {
        json = {
            {"transfer_id", response.transfer_id},
            {"offset", response.offset},
            {"bytes", response.bytes},
            {"done", response.done},
            {"data", response.data_base64},
            {"hash", response.chunk_hash},
        };
    }

    void from_json(const nlohmann::json &json, DownloadChunkResponse &response)
    {
        response.transfer_id = json.at("transfer_id").get<std::string>();
        response.offset = json.value("offset", 0ULL);
        response.bytes = json.value("bytes", 0ULL);
        response.done = json.value("done", false);
        response.data_base64 = json.value("data", std::string{});
        response.chunk_hash = json.value("hash", std::string{});
    }

} // namespace minidrive::protocol
