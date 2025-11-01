#include "minidrive/encoding/base64.hpp"

#include <array>
#include <cstdint>
#include <cctype>

namespace minidrive::encoding
{

    namespace
    {

        constexpr std::array<char, 64> kAlphabet = {
            'A',
            'B',
            'C',
            'D',
            'E',
            'F',
            'G',
            'H',
            'I',
            'J',
            'K',
            'L',
            'M',
            'N',
            'O',
            'P',
            'Q',
            'R',
            'S',
            'T',
            'U',
            'V',
            'W',
            'X',
            'Y',
            'Z',
            'a',
            'b',
            'c',
            'd',
            'e',
            'f',
            'g',
            'h',
            'i',
            'j',
            'k',
            'l',
            'm',
            'n',
            'o',
            'p',
            'q',
            'r',
            's',
            't',
            'u',
            'v',
            'w',
            'x',
            'y',
            'z',
            '0',
            '1',
            '2',
            '3',
            '4',
            '5',
            '6',
            '7',
            '8',
            '9',
            '+',
            '/',
        };

        consteval auto make_decode_table()
        {
            std::array<int8_t, 256> table{};
            table.fill(-1);
            for (std::size_t i = 0; i < kAlphabet.size(); ++i)
            {
                table[static_cast<unsigned char>(kAlphabet[i])] = static_cast<int8_t>(i);
            }
            table[static_cast<unsigned char>('=')] = -2;
            return table;
        }

        constexpr auto kDecodeTable = make_decode_table();

    } // namespace

    std::string encode_base64(std::span<const std::byte> data)
    {
        std::string output;
        output.reserve(((data.size() + 2) / 3) * 4);

        std::uint32_t buffer = 0;
        int bits_collected = 0;

        for (const auto byte : data)
        {
            buffer = (buffer << 8u) | static_cast<std::uint32_t>(byte);
            bits_collected += 8;
            while (bits_collected >= 6)
            {
                bits_collected -= 6;
                const auto index = static_cast<std::size_t>((buffer >> bits_collected) & 0x3Fu);
                output.push_back(kAlphabet[index]);
            }
        }

        if (bits_collected > 0)
        {
            buffer <<= (6 - bits_collected);
            const auto index = static_cast<std::size_t>(buffer & 0x3F);
            output.push_back(kAlphabet[index]);
        }

        while (output.size() % 4 != 0)
        {
            output.push_back('=');
        }

        return output;
    }

    std::vector<std::byte> decode_base64(std::string_view input)
    {
        std::vector<std::byte> output;
        output.reserve((input.size() * 3) / 4);

        std::uint32_t accumulator = 0;
        int bits_collected = 0;
        for (const char ch : input)
        {
            const auto c = static_cast<unsigned char>(ch);
            const int value = kDecodeTable[c];
            if (value == -1)
            {
                if (!std::isspace(c))
                {
                    return {};
                }
                continue;
            }
            if (value == -2)
            {
                break;
            }
            accumulator = (accumulator << 6) | static_cast<std::uint32_t>(value);
            bits_collected += 6;
            if (bits_collected >= 8)
            {
                bits_collected -= 8;
                const auto byte_value = static_cast<std::uint8_t>((accumulator >> bits_collected) & 0xFFu);
                output.push_back(static_cast<std::byte>(byte_value));
            }
        }

        return output;
    }

} // namespace minidrive::encoding
