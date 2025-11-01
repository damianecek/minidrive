#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "minidrive/protocol.hpp"

namespace minidrive::server::session_common
{

    std::uint64_t to_unix_time(const std::filesystem::file_time_type &time);

    std::string relative_path_or_dot(const std::filesystem::path &base, const std::filesystem::path &target);

    minidrive::protocol::ResponseEnvelope make_ok_response(nlohmann::json payload,
                                                           const std::optional<std::string> &request_id);

} // namespace minidrive::server::session_common
