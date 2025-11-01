#include "session_common.hpp"

#include <chrono>

#include "minidrive/crypto.hpp"
#include "minidrive/error_codes.hpp"

namespace minidrive::server::session_common
{

    std::uint64_t to_unix_time(const std::filesystem::file_time_type &time)
    {
        using namespace std::chrono;
        const auto system_time = time_point_cast<seconds>(time - std::filesystem::file_time_type::clock::now() +
                                                          std::chrono::system_clock::now());
        return static_cast<std::uint64_t>(system_time.time_since_epoch().count());
    }

    std::string relative_path_or_dot(const std::filesystem::path &base, const std::filesystem::path &target)
    {
        auto rel = target.lexically_relative(base);
        auto str = rel.generic_string();
        if (str.empty() || str == ".")
        {
            return ".";
        }
        return str;
    }

    minidrive::protocol::ResponseEnvelope make_ok_response(nlohmann::json payload,
                                                           const std::optional<std::string> &request_id)
    {
        minidrive::protocol::ResponseEnvelope envelope;
        envelope.kind = minidrive::protocol::ResponseKind::Ok;
        envelope.payload = std::move(payload);
        envelope.message = "";
        envelope.error = minidrive::ErrorCode::Ok;
        envelope.request_id = request_id;
        return envelope;
    }

} // namespace minidrive::server::session_common
