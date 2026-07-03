#pragma once
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace era::bech32 {

// Encode data with the given human-readable part.
// The HRP must be valid (1-83 chars, ASCII 33-126).
[[nodiscard]] auto encode(std::string_view hrp, std::span<const std::byte> data) -> std::string;

// Decode a Bech32 string. Returns {hrp, data} on success, std::nullopt on error.
// Per the age spec, no length limits are imposed on the data part.
[[nodiscard]] auto decode(std::string_view str) -> std::optional<std::pair<std::string, std::vector<std::byte>>>;

// Convert 8-bit words to 5-bit words (for data part encoding).
[[nodiscard]] auto convert_bits(std::span<const std::byte> data, unsigned from_bits, unsigned to_bits, bool pad) -> std::optional<std::vector<uint8_t>>;

} // namespace era::bech32
