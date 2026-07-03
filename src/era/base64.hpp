#pragma once
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace era::base64 {

// Encode binary data to canonical (unpadded) base64 per RFC 4648 §4.
// This is the format used in age headers (no padding).
[[nodiscard]] auto encode(std::span<const std::byte> data) -> std::string;

// Decode canonical (unpadded) base64. Returns std::nullopt on any error
// (non-canonical encoding, invalid chars, padding, etc.).
[[nodiscard]] auto decode(std::string_view encoded) -> std::optional<std::vector<std::byte>>;

// Encode with standard padding (used for ASCII armor).
[[nodiscard]] auto encode_padded(std::span<const std::byte> data) -> std::string;

// Decode padded base64. Returns std::nullopt on error.
[[nodiscard]] auto decode_padded(std::string_view encoded) -> std::optional<std::vector<std::byte>>;

} // namespace era::base64
