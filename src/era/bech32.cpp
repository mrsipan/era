#include "era/bech32.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <numeric>
#include <stdexcept>

namespace era::bech32 {
namespace {

constexpr std::string_view kCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Bech32 checksum generator polynomial coefficients
constexpr auto kGenerator = std::array<uint32_t, 5>{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

auto polymod(std::span<const uint8_t> values) -> uint32_t {
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t top = static_cast<uint8_t>(chk >> 25);
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (size_t i = 0; i < 5; ++i) {
            if ((top >> i) & 1) chk ^= kGenerator[i];
        }
    }
    return chk;
}

auto hrp_expand(std::string_view hrp) -> std::vector<uint8_t> {
    std::vector<uint8_t> expanded;
    expanded.reserve(hrp.size() * 2 + 1);
    for (char c : hrp) {
        expanded.push_back(static_cast<uint8_t>(c) >> 5);
    }
    expanded.push_back(0);
    for (char c : hrp) {
        expanded.push_back(static_cast<uint8_t>(c) & 0x1f);
    }
    return expanded;
}

auto verify_checksum(std::string_view hrp, std::span<const uint8_t> data) -> bool {
    auto expanded = hrp_expand(hrp);
    std::vector<uint8_t> values;
    values.reserve(expanded.size() + data.size());
    values.insert(values.end(), expanded.begin(), expanded.end());
    values.insert(values.end(), data.begin(), data.end());
    return polymod(values) == 1;
}

auto create_checksum(std::string_view hrp, std::span<const uint8_t> data) -> std::array<uint8_t, 6> {
    auto expanded = hrp_expand(hrp);
    std::vector<uint8_t> values;
    values.reserve(expanded.size() + data.size() + 6);
    values.insert(values.end(), expanded.begin(), expanded.end());
    values.insert(values.end(), data.begin(), data.end());
    values.resize(values.size() + 6, 0); // 6 zero bytes for checksum

    uint32_t mod = polymod(values) ^ 1;
    std::array<uint8_t, 6> checksum{};
    for (size_t i = 0; i < 6; ++i) {
        checksum[i] = static_cast<uint8_t>((mod >> (5 * (5 - i))) & 31);
    }
    return checksum;
}

} // anonymous namespace

auto convert_bits(std::span<const std::byte> data, unsigned from_bits, unsigned to_bits, bool pad) -> std::optional<std::vector<uint8_t>> {
    uint32_t acc = 0;
    unsigned bits = 0;
    uint32_t maxv = (1u << to_bits) - 1;
    uint32_t max_acc = (1u << (from_bits + to_bits - 1)) - 1;
    std::vector<uint8_t> result;

    for (auto b : data) {
        uint8_t value = static_cast<uint8_t>(b);
        if ((value >> from_bits) != 0) return std::nullopt; // value doesn't fit in from_bits

        acc = ((acc << from_bits) | value) & max_acc;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            result.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
        }
    }
    if (pad) {
        if (bits > 0) {
            result.push_back(static_cast<uint8_t>((acc << (to_bits - bits)) & maxv));
        }
    } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0) {
        return std::nullopt;
    }

    return result;
}

auto encode(std::string_view hrp, std::span<const std::byte> data) -> std::string {
    // Validate HRP
    if (hrp.empty() || hrp.size() > 83) {
        throw std::invalid_argument("HRP must be 1-83 characters");
    }
    for (char c : hrp) {
        if (c < 33 || c > 126) throw std::invalid_argument("HRP contains invalid character");
    }

    // Lowercase HRP for checksum computation (Bech32 spec)
    std::string lower_hrp(hrp);
    std::transform(lower_hrp.begin(), lower_hrp.end(), lower_hrp.begin(), ::tolower);

    // Convert 8-bit data to 5-bit
    auto converted = convert_bits(data, 8, 5, true);
    if (!converted) throw std::invalid_argument("data conversion failed");

    // Compute checksum using lowercase HRP
    auto checksum = create_checksum(lower_hrp, *converted);

    // Build output: hrp + "1" + data5 + checksum
    // The output must be all uppercase or all lowercase.
    // We detect the case from the HRP and apply to data.
    bool upper = std::any_of(hrp.begin(), hrp.end(), [](char c) { return c >= 'A' && c <= 'Z'; });
    std::string result;
    result.reserve(hrp.size() + 1 + converted->size() + 6);
    result = std::string(hrp);  // keep original case
    result += '1';
    for (uint8_t v : *converted) result += kCharset[v];
    for (uint8_t v : checksum) result += kCharset[v];
    if (upper) {
        // Convert data part to uppercase (HRP already is)
        for (size_t i = hrp.size() + 1; i < result.size(); ++i) {
            result[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(result[i])));
        }
    }

    return result;
}

auto decode(std::string_view str) -> std::optional<std::pair<std::string, std::vector<std::byte>>> {
    // Must be lowercase or uppercase, but not mixed
    bool has_lower = false, has_upper = false;
    for (char c : str) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        else if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper) return std::nullopt;

    // Convert to lowercase for processing
    std::string lower(str);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Find separator
    auto sep_pos = lower.rfind('1');
    if (sep_pos == std::string::npos || sep_pos == 0 || sep_pos + 7 > lower.size()) {
        return std::nullopt;
    }

    std::string hrp = lower.substr(0, sep_pos);

    // Validate HRP
    if (hrp.size() > 83) return std::nullopt;
    for (char c : hrp) {
        if (c < 33 || c > 126) return std::nullopt;
    }

    // Parse data part (5-bit values)
    std::vector<uint8_t> data5;
    data5.reserve(lower.size() - sep_pos - 1);
    for (size_t i = sep_pos + 1; i < lower.size(); ++i) {
        char c = lower[i];
        auto pos = kCharset.find(c);
        if (pos == std::string_view::npos) return std::nullopt;
        data5.push_back(static_cast<uint8_t>(pos));
    }

    // Verify checksum (last 6 bytes are checksum)
    if (!verify_checksum(hrp, data5)) return std::nullopt;

    // Remove checksum
    data5.resize(data5.size() - 6);

    // Convert 5-bit to 8-bit
    auto data8 = convert_bits(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(data5.data()), data5.size()),
        5, 8, false);
    if (!data8) return std::nullopt;

    std::vector<std::byte> result;
    result.reserve(data8->size());
    for (uint8_t v : *data8) result.push_back(static_cast<std::byte>(v));

    return std::make_pair(hrp, std::move(result));
}

} // namespace era::bech32
