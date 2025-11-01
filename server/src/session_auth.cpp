#include "minidrive/server/session.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "session_common.hpp"

namespace minidrive::server
{

    void Session::handle_authenticate(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (authenticated_)
        {
            send_error(minidrive::ErrorCode::Conflict, "Already authenticated", envelope.request_id);
            return;
        }

        minidrive::protocol::AuthenticateRequest request;
        try
        {
            request = envelope.payload.get<minidrive::protocol::AuthenticateRequest>();
        }
        catch (const std::exception &ex)
        {
            send_error(minidrive::ErrorCode::InvalidPayload, ex.what(), envelope.request_id);
            return;
        }

        std::string identity = request.public_mode ? std::string{"public"} : request.username;
        if (identity.empty())
        {
            send_error(minidrive::ErrorCode::InvalidPayload, "Username is required", envelope.request_id);
            return;
        }

        if (!request.public_mode)
        {
            if (request.register_user)
            {
                std::string message;
                if (!services_.user_store.register_user(request.username, request.password, message))
                {
                    send_error(minidrive::ErrorCode::Conflict, message, envelope.request_id);
                    return;
                }
            }
            if (!services_.user_store.authenticate(request.username, request.password))
            {
                send_error(minidrive::ErrorCode::AuthenticationFailed, "Invalid credentials", envelope.request_id);
                return;
            }
        }

        session_paths_ = services_.filesystem.prepare_session_paths(identity, request.public_mode);

        if (!services_.session_manager.try_register(identity, shared_from_this()))
        {
            send_error(minidrive::ErrorCode::Busy, "Session already active", envelope.request_id);
            return;
        }

        authenticated_ = true;
        minidrive::protocol::AuthenticateResponse response{
            .success = true,
            .newly_registered = request.register_user && !request.public_mode,
            .identity = identity,
        };
        nlohmann::json payload = response;
        send_response(session_common::make_ok_response(std::move(payload), envelope.request_id));
        spdlog::info("Session authenticated as {} ({})", session_paths_.identity, remote_endpoint());
    }

} // namespace minidrive::server
