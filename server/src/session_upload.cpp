#include "minidrive/server/session.hpp"

#include <nlohmann/json.hpp>

#include "minidrive/encoding/base64.hpp"
#include "session_common.hpp"

namespace minidrive::server
{

    void Session::handle_upload_init(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            services_.transfer_registry.cleanup_expired(services_.upload_timeout);
            const auto request = envelope.payload.get<minidrive::protocol::UploadInitRequest>();
            const auto target = services_.filesystem.resolve_for_new_entry(session_paths_, request.remote_path);
            auto info = services_.transfer_registry.create_or_resume(session_paths_.identity, target, request.file_size,
                                                                     request.chunk_size, request.root_hash, request.resume);

            minidrive::protocol::TransferDescriptor descriptor{
                .transfer_id = info.state.transfer_id,
                .total_size = info.state.file_size,
                .chunk_size = info.state.chunk_size,
                .root_hash = info.state.root_hash,
            };

            nlohmann::json payload;
            payload["descriptor"] = descriptor;
            payload["bytes_written"] = info.state.bytes_written;
            payload["resumed"] = info.resumed;
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

    void Session::handle_upload_chunk(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::UploadChunkRequest>();
            const auto data = minidrive::encoding::decode_base64(request.data_base64);
            if (data.empty() && !request.data_base64.empty())
            {
                send_error(minidrive::ErrorCode::InvalidPayload, "Invalid chunk data", envelope.request_id);
                return;
            }
            std::string error_message;
            if (!services_.transfer_registry.append_chunk(request.transfer_id, request.offset, data, request.chunk_hash,
                                                          error_message))
            {
                send_error(minidrive::ErrorCode::InvalidPayload, error_message, envelope.request_id);
                return;
            }
            nlohmann::json payload;
            payload["bytes"] = data.size();
            send_response(session_common::make_ok_response(payload, envelope.request_id));
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_upload_commit(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::UploadCommitRequest>();
            std::string error_message;
            if (!services_.transfer_registry.commit(request.transfer_id, request.final_hash, error_message))
            {
                send_error(minidrive::ErrorCode::InvalidPayload, error_message, envelope.request_id);
                return;
            }
            send_response(session_common::make_ok_response(nlohmann::json::object(), envelope.request_id));
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

} // namespace minidrive::server
