#include "minidrive/error_codes.hpp"

#include <array>

namespace minidrive
{

    namespace
    {
        struct ErrorCodeDescription
        {
            ErrorCode code;
            std::string_view description;
        };

        constexpr std::array<ErrorCodeDescription, 14> kDescriptions{{
            {ErrorCode::Ok, "ok"},
            {ErrorCode::InvalidCommand, "invalid_command"},
            {ErrorCode::InvalidPayload, "invalid_payload"},
            {ErrorCode::PermissionDenied, "permission_denied"},
            {ErrorCode::NotFound, "not_found"},
            {ErrorCode::AlreadyExists, "already_exists"},
            {ErrorCode::AuthenticationRequired, "authentication_required"},
            {ErrorCode::AuthenticationFailed, "authentication_failed"},
            {ErrorCode::Conflict, "conflict"},
            {ErrorCode::Busy, "busy"},
            {ErrorCode::ResumeStateInvalid, "resume_state_invalid"},
            {ErrorCode::Unsupported, "unsupported"},
            {ErrorCode::Timeout, "timeout"},
            {ErrorCode::InternalError, "internal_error"},
        }};
    } // namespace

    std::string_view to_string(ErrorCode code) noexcept
    {
        for (const auto &entry : kDescriptions)
        {
            if (entry.code == code)
            {
                return entry.description;
            }
        }
        return "unknown";
    }

    ErrorCode error_code_from_int(std::uint16_t value) noexcept
    {
        for (const auto &entry : kDescriptions)
        {
            if (static_cast<std::uint16_t>(entry.code) == value)
            {
                return entry.code;
            }
        }
        return ErrorCode::InternalError;
    }

} // namespace minidrive
