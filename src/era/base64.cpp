#include "era/base64.hpp"
#include <algorithm>
#include <array>
#include <cstdint>

namespace era::base64 {
namespace {

// RFC 4648 §4 alphabet
constexpr std::string_view kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Decode lookup table: maps char -> 6-bit value, or 0xFF on invalid.
constexpr auto make_decode_table() -> std::array<uint8_t, 256> {
    std::array<uint8_t, 256> table{};
    table.fill(0xFF);
    for (size_t i = 0; i < 64; ++i) {
        table[static_cast<uint8_t>(kAlphabet[i])] = static_cast<uint8_t>(i);
    }
    return table;
}
constexpr auto kDecodeTable = make_decode_table();

// Check if an encoded string uses only canonical alphabet characters.
// Padding ('=') is NOT allowed in unpadded base64.
[[nodiscard]] auto is_canonical(std::string_view s) -> bool {
    for (char c : s) {
        if (static_cast<uint8_t>(c) > 127) return false;
        if (kDecodeTable[static_cast<uint8_t>(c)] == 0xFF) return false;
    }
    return true;
}

// Check for padded base64 (allows '=' padding).
[[nodiscard]] auto is_canonical_padded(std::string_view s) -> bool {
    size_t pad_start = s.size();
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '=') {
            pad_start = i;
            break;
        }
        if (static_cast<uint8_t>(c) > 127) return false;
        if (kDecodeTable[static_cast<uint8_t>(c)] == 0xFF) return false;
    }
    // Validate padding
    for (size_t i = pad_start; i < s.size(); ++i) {
        if (s[i] != '=') return false;
    }
    size_t pad_len = s.size() - pad_start;
    if (pad_len > 2) return false;
    // Valid padding: 2 pad chars means (len-2) % 4 == 2; 1 pad char means (len-1) % 4 == 3
    if (pad_len == 2 && (s.size() - 2) % 4 != 2) return false;
    if (pad_len == 1 && (s.size() - 1) % 4 != 3) return false;
    return true;
}

} // anonymous namespace

auto encode(std::span<const std::byte> data) -> std::string {
    std::string result;
    size_t out_len = (data.size() + 2) / 3 * 4;
    // For unpadded, strip trailing 'A's (which are actually '=' in padded).
    // Actually we compute padded first then strip padding.
    result.reserve(out_len);

    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = static_cast<uint32_t>(static_cast<uint8_t>(data[i])) << 16;
        size_t remaining = data.size() - i;
        if (remaining >= 2) n |= static_cast<uint32_t>(static_cast<uint8_t>(data[i + 1])) << 8;
        if (remaining >= 3) n |= static_cast<uint32_t>(static_cast<uint8_t>(data[i + 2]));

        result.push_back(kAlphabet[(n >> 18) & 0x3F]);
        result.push_back(kAlphabet[(n >> 12) & 0x3F]);
        if (remaining >= 2) result.push_back(kAlphabet[(n >> 6) & 0x3F]);
        if (remaining >= 3) result.push_back(kAlphabet[n & 0x3F]);
    }

    return result;
}

auto decode(std::string_view encoded) -> std::optional<std::vector<std::byte>> {
    if (!is_canonical(encoded)) return std::nullopt;

    // For canonical base64, the encoded length determines the decoded length.
    size_t out_len = encoded.size() * 3 / 4;
    // But we need to check if the last quantum is partial.
    switch (encoded.size() % 4) {
        case 0: break;
        case 1: return std::nullopt; // incomplete quantum
        case 2: out_len = encoded.size() / 4 * 3 + 1; break;
        case 3: out_len = encoded.size() / 4 * 3 + 2; break;
    }

    std::vector<std::byte> result;
    result.reserve(out_len);

    for (size_t i = 0; i < encoded.size(); i += 4) {
        uint32_t n = 0;
        size_t chars_in_quantum = std::min(size_t{4}, encoded.size() - i);

        n |= static_cast<uint32_t>(kDecodeTable[static_cast<uint8_t>(encoded[i])]) << 18;
        if (chars_in_quantum >= 2)
            n |= static_cast<uint32_t>(kDecodeTable[static_cast<uint8_t>(encoded[i + 1])]) << 12;
        if (chars_in_quantum >= 3)
            n |= static_cast<uint32_t>(kDecodeTable[static_cast<uint8_t>(encoded[i + 2])]) << 6;
        if (chars_in_quantum >= 4)
            n |= static_cast<uint32_t>(kDecodeTable[static_cast<uint8_t>(encoded[i + 3])]);

        result.push_back(static_cast<std::byte>((n >> 16) & 0xFF));
        if (chars_in_quantum >= 3)
            result.push_back(static_cast<std::byte>((n >> 8) & 0xFF));
        if (chars_in_quantum >= 4)
            result.push_back(static_cast<std::byte>(n & 0xFF));
    }

    return result;
}

auto encode_padded(std::span<const std::byte> data) -> std::string {
    std::string result = encode(data);
    // Add padding
    switch (data.size() % 3) {
        case 1: result += "=="; break;
        case 2: result += "="; break;
        default: break;
    }
    return result;
}

auto decode_padded(std::string_view encoded) -> std::optional<std::vector<std::byte>> {
    if (!is_canonical_padded(encoded)) return std::nullopt;

    // Strip padding for decode
    std::string stripped(encoded);
    while (!stripped.empty() && stripped.back() == '=') {
        stripped.pop_back();
    }

    return decode(stripped);
}

} // namespace era::base64
