/**
 * MiniDrive - Crypto helpers built on libsodium.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <istream>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace minidrive::crypto
{

    void ensure_sodium_init();

    std::string hash_password(std::string_view password);

    bool verify_password(std::string_view password, std::string_view password_hash);

    std::string hash_bytes(std::span<const std::byte> data);

    std::string hash_stream(std::istream &input);

    std::string hash_file(const std::filesystem::path &path);

} // namespace minidrive::crypto