#include "minidrive/server/session.hpp"

#include <nlohmann/json.hpp>

#include "session_common.hpp"

namespace minidrive::server
{

    void Session::handle_list(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::ListRequest>();
            const auto entries = services_.filesystem.list_directory(session_paths_, request.path);
            nlohmann::json payload; // default object
            payload["entries"] = entries;
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

    void Session::handle_stat(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::PathRequest>();
            const auto info = services_.filesystem.stat_path(session_paths_, request.path);
            nlohmann::json payload;
            payload["metadata"] = info;
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

    void Session::handle_mkdir(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::PathRequest>();
            services_.filesystem.create_directory(session_paths_, request.path);
            send_response(session_common::make_ok_response(nlohmann::json::object(), envelope.request_id));
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

    void Session::handle_rmdir(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::PathRequest>();
            services_.filesystem.remove_directory(session_paths_, request.path);
            send_response(session_common::make_ok_response(nlohmann::json::object(), envelope.request_id));
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

    void Session::handle_move(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::MoveCopyRequest>();
            services_.filesystem.move_path(session_paths_, request.source, request.destination);
            send_response(session_common::make_ok_response(nlohmann::json::object(), envelope.request_id));
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

    void Session::handle_copy(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::MoveCopyRequest>();
            services_.filesystem.copy_path(session_paths_, request.source, request.destination);
            send_response(session_common::make_ok_response(nlohmann::json::object(), envelope.request_id));
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

    void Session::handle_delete(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::PathRequest>();
            services_.filesystem.remove_file(session_paths_, request.path);
            send_response(session_common::make_ok_response(nlohmann::json::object(), envelope.request_id));
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

} // namespace minidrive::server
