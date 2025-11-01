#include "minidrive/framing.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace minidrive::protocol
{

    namespace
    {
        constexpr std::size_t kHeaderSize = sizeof(std::uint32_t);

        std::uint32_t read_u32_be(std::span<const std::uint8_t> buffer)
        {
            return (static_cast<std::uint32_t>(buffer[0]) << 24) |
                   (static_cast<std::uint32_t>(buffer[1]) << 16) |
                   (static_cast<std::uint32_t>(buffer[2]) << 8) |
                   static_cast<std::uint32_t>(buffer[3]);
        }

        void write_u32_be(std::uint32_t value, std::span<std::uint8_t> buffer)
        {
            buffer[0] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
            buffer[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
            buffer[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
            buffer[3] = static_cast<std::uint8_t>(value & 0xFF);
        }
    } // namespace

    std::vector<std::uint8_t> encode_frame(const nlohmann::json &message)
    {
        const auto text = message.dump();
        if (text.size() > std::numeric_limits<std::uint32_t>::max())
        {
            throw std::length_error("JSON message too large to frame");
        }
        std::vector<std::uint8_t> frame(kHeaderSize + text.size());
        write_u32_be(static_cast<std::uint32_t>(text.size()), std::span<std::uint8_t>(frame).first<kHeaderSize>());
        std::copy(text.begin(), text.end(), frame.begin() + static_cast<std::ptrdiff_t>(kHeaderSize));
        return frame;
    }

    std::optional<DecodedFrame> try_decode_frame(std::span<const std::uint8_t> buffer)
    {
        if (buffer.size() < kHeaderSize)
        {
            return std::nullopt;
        }
        const auto payload_size = read_u32_be(buffer.first<kHeaderSize>());
        if (buffer.size() < kHeaderSize + payload_size)
        {
            return std::nullopt;
        }
        const auto payload_begin = buffer.begin() + static_cast<std::ptrdiff_t>(kHeaderSize);
        const std::string payload(payload_begin, payload_begin + payload_size);
        DecodedFrame result{
            .message = nlohmann::json::parse(payload),
            .bytes_consumed = kHeaderSize + payload_size,
        };
        return result;
    }

} // namespace minidrive::protocol
