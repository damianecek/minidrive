#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace minidrive::encoding
{

    std::string encode_base64(std::span<const std::byte> data);

    std::vector<std::byte> decode_base64(std::string_view input);

} // namespace minidrive::encoding
