#pragma once
#include "era/crypto.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace era::format {

// ---- Constants ----
inline constexpr std::string_view kVersionLine = "age-encryption.org/v1\n";
inline constexpr size_t kChunkSize = 64 * 1024; // 64 KiB
inline constexpr std::string_view kPemLabel = "AGE ENCRYPTED FILE";

// ---- Stanza types ----
enum class StanzaType {
    X25519,
    Scrypt,
    Unknown,
};

struct Stanza {
    StanzaType type;
    std::vector<std::string> args;       // space-separated arguments
    std::vector<std::byte> body;         // base64-decoded body
    std::string raw;                     // raw stanza text (for header MAC)
};

// ---- Header ----
struct Header {
    std::vector<Stanza> stanzas;
    std::array<std::byte, 32> mac;      // header MAC
};

// Parse a complete age header from a reader that provides bytes sequentially.
// Returns Header on success, std::nullopt on parse error.
// The reader should provide the raw header bytes.
[[nodiscard]] auto parse_header(std::string_view header_text) -> std::optional<Header>;

// Serialize a header (version line + stanzas + "--- " prefix, without the MAC).
// The caller must compute and append the base64-encoded MAC.
[[nodiscard]] auto serialize_header(const Header& header) -> std::string;

// Compute the header MAC. header_up_to_mac includes the version line, stanzas,
// and ends with "---" (3 dashes, no trailing space) per the age spec.
[[nodiscard]] auto compute_header_mac(std::string_view header_up_to_dashes, const crypto::FileKey& file_key) -> std::array<std::byte, 32>;

// ---- Payload ----
// Encrypt payload in streaming fashion.
// Returns encrypted payload as: nonce (16) || encrypted_data
[[nodiscard]] auto encrypt_payload(
    const crypto::FileKey& file_key,
    std::span<const std::byte> nonce,   // 16-byte random nonce
    std::span<const std::byte> plaintext
) -> std::optional<crypto::Bytes>;

// Decrypt payload. Input: nonce (16) || encrypted_data
[[nodiscard]] auto decrypt_payload(
    const crypto::FileKey& file_key,
    std::span<const std::byte> payload_with_nonce
) -> std::optional<crypto::Bytes>;

// ---- ASCII Armor ----
// Encode data as PEM (RFC 7468, strict).
[[nodiscard]] auto armor(std::span<const std::byte> data) -> std::string;

// Decode PEM-encoded data. Returns std::nullopt on strict parse error.
[[nodiscard]] auto dearmor(std::string_view pem) -> std::optional<crypto::Bytes>;

} // namespace era::format
