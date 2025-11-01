/**
 * MiniDrive - Shared error codes used across client and server layers.
 */
#pragma once

#include <cstdint>
#include <string_view>

namespace minidrive
{

    enum class ErrorCode : std::uint16_t
    {
        Ok = 0,
        InvalidCommand = 1,
        InvalidPayload = 2,
        PermissionDenied = 3,
        NotFound = 4,
        AlreadyExists = 5,
        AuthenticationRequired = 6,
        AuthenticationFailed = 7,
        Conflict = 8,
        Busy = 9,
        ResumeStateInvalid = 10,
        Unsupported = 11,
        Timeout = 12,
        InternalError = 13
    };

    std::string_view to_string(ErrorCode code) noexcept;

    constexpr std::uint16_t to_int(ErrorCode code) noexcept
    {
        return static_cast<std::uint16_t>(code);
    }

    ErrorCode error_code_from_int(std::uint16_t value) noexcept;

} // namespace minidrive
