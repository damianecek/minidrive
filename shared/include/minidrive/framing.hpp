/**
 * MiniDrive - Length-prefixed JSON framing helpers.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <nlohmann/json.hpp>

namespace minidrive::protocol
{

    struct DecodedFrame
    {
        nlohmann::json message;
        std::size_t bytes_consumed{};
    };

    std::vector<std::uint8_t> encode_frame(const nlohmann::json &message);

    std::optional<DecodedFrame> try_decode_frame(std::span<const std::uint8_t> buffer);

} // namespace minidrive::protocol
