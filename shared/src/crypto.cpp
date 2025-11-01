#include "minidrive/crypto.hpp"

#include <cstring>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <vector>

#include <sodium.h>

namespace minidrive::crypto
{

    namespace
    {

        void throw_if_sodium_init_failed(int status)
        {
            if (status < 0)
            {
                throw std::runtime_error("libsodium initialization failed");
            }
        }

        std::string to_hex(std::span<const unsigned char> data)
        {
            static constexpr char kHexDigits[] = "0123456789abcdef";
            std::string result;
            result.resize(data.size() * 2);
            for (std::size_t i = 0; i < data.size(); ++i)
            {
                const auto byte = data[i];
                result[2 * i] = kHexDigits[(byte >> 4) & 0x0F];
                result[2 * i + 1] = kHexDigits[byte & 0x0F];
            }
            return result;
        }

        std::once_flag &sodium_once_flag()
        {
            static std::once_flag flag;
            return flag;
        }

        void ensure_initialized_once()
        {
            std::call_once(sodium_once_flag(), []()
                           { throw_if_sodium_init_failed(sodium_init()); });
        }

    } // namespace

    void ensure_sodium_init()
    {
        ensure_initialized_once();
    }

    std::string hash_password(std::string_view password)
    {
        ensure_initialized_once();
        std::string hash;
        hash.resize(crypto_pwhash_STRBYTES);
        if (crypto_pwhash_str(hash.data(), password.data(), password.size(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
                              crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
        {
            throw std::runtime_error("crypto_pwhash_str failed");
        }
        hash.resize(std::strlen(hash.c_str()));
        return hash;
    }

    bool verify_password(std::string_view password, std::string_view password_hash)
    {
        ensure_initialized_once();
        const std::string hash_string(password_hash);
        return crypto_pwhash_str_verify(hash_string.c_str(), password.data(), password.size()) == 0;
    }

    std::string hash_bytes(std::span<const std::byte> data)
    {
        ensure_initialized_once();
        std::vector<unsigned char> digest(crypto_generichash_BYTES);
        if (crypto_generichash(digest.data(), digest.size(),
                               reinterpret_cast<const unsigned char *>(data.data()), data.size(), nullptr, 0) != 0)
        {
            throw std::runtime_error("crypto_generichash failed");
        }
        return to_hex(digest);
    }

    std::string hash_stream(std::istream &input)
    {
        ensure_initialized_once();
        crypto_generichash_state state;
        if (crypto_generichash_init(&state, nullptr, 0, crypto_generichash_BYTES) != 0)
        {
            throw std::runtime_error("crypto_generichash_init failed");
        }

        std::vector<unsigned char> buffer(64 * 1024);
        while (input)
        {
            input.read(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
            const auto read_count = static_cast<std::size_t>(input.gcount());
            if (read_count > 0)
            {
                if (crypto_generichash_update(&state, buffer.data(), read_count) != 0)
                {
                    throw std::runtime_error("crypto_generichash_update failed");
                }
            }
        }

        std::vector<unsigned char> digest(crypto_generichash_BYTES);
        if (crypto_generichash_final(&state, digest.data(), digest.size()) != 0)
        {
            throw std::runtime_error("crypto_generichash_final failed");
        }
        return to_hex(digest);
    }

    std::string hash_file(const std::filesystem::path &path)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open())
        {
            throw std::runtime_error("Failed to open file for hashing: " + path.string());
        }
        return hash_stream(file);
    }

} // namespace minidrive::crypto
