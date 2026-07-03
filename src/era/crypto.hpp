#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace era::crypto {

// ---- Constants ----
inline constexpr size_t kX25519KeyLen = 32;      // X25519 public/private key length
inline constexpr size_t kFileKeyLen = 16;         // File key length (128 bits)
inline constexpr size_t kChachaKeyLen = 32;       // ChaCha20 key length (256 bits)
inline constexpr size_t kChachaNonceLen = 12;     // ChaCha20-Poly1305 nonce length
inline constexpr size_t kChachaTagLen = 16;       // Poly1305 tag length
inline constexpr size_t kScryptSaltLen = 16;      // scrypt salt length
inline constexpr size_t kHkdfOutputLen = 32;      // HKDF output length
inline constexpr size_t kPayloadNonceLen = 16;    // Payload nonce prefix length

// Buffer type aliases
using Bytes = std::vector<std::byte>;
using FileKey = std::array<std::byte, kFileKeyLen>;
using X25519Key = std::array<std::byte, kX25519KeyLen>;

// ---- Random bytes ----
[[nodiscard]] auto random(size_t n) -> Bytes;
[[nodiscard]] auto random_file_key() -> FileKey;
[[nodiscard]] auto random_x25519_key() -> X25519Key;
[[nodiscard]] auto random_scrypt_salt() -> std::array<std::byte, kScryptSaltLen>;
[[nodiscard]] auto random_payload_nonce() -> std::array<std::byte, kPayloadNonceLen>;

// ---- X25519 ----
// Generate a new X25519 keypair.
struct X25519Keypair {
    X25519Key public_key;   // 32 bytes
    X25519Key secret_key;   // 32 bytes
};
[[nodiscard]] auto x25519_keygen() -> X25519Keypair;

// Compute X25519(scalar, point). Both must be 32 bytes.
[[nodiscard]] auto x25519(std::span<const std::byte> scalar, std::span<const std::byte> point) -> std::optional<X25519Key>;

// ---- ChaCha20-Poly1305 AEAD ----
// Encrypt plaintext with key and nonce. Returns ciphertext || tag.
[[nodiscard]] auto chacha20_poly1305_encrypt(
    std::span<const std::byte> key,
    std::span<const std::byte> nonce, // 12 bytes
    std::span<const std::byte> plaintext
) -> std::optional<Bytes>;

// Decrypt ciphertext with key and nonce. Ciphertext includes trailing 16-byte tag.
[[nodiscard]] auto chacha20_poly1305_decrypt(
    std::span<const std::byte> key,
    std::span<const std::byte> nonce, // 12 bytes
    std::span<const std::byte> ciphertext_with_tag
) -> std::optional<Bytes>;

// ---- HKDF-SHA-256 ----
// HKDF-Extract + HKDF-Expand producing `length` bytes.
[[nodiscard]] auto hkdf_sha256(
    std::span<const std::byte> ikm,      // input keying material
    std::span<const std::byte> salt,     // salt (may be empty)
    std::span<const std::byte> info,     // info string
    size_t length = kHkdfOutputLen
) -> Bytes;

// ---- HMAC-SHA-256 ----
[[nodiscard]] auto hmac_sha256(
    std::span<const std::byte> key,
    std::span<const std::byte> data
) -> std::array<std::byte, 32>;

// ---- scrypt ----
// Derive key from passphrase using scrypt.
// N = work factor (power of 2), r = 8, p = 1.
// Salt includes the "age-encryption.org/v1/scrypt" prefix.
[[nodiscard]] auto scrypt(
    std::string_view passphrase,
    std::span<const std::byte> salt,     // full salt (prefix + 16 random bytes)
    uint64_t N,                          // CPU/memory cost factor
    size_t dklen = 32
) -> std::optional<Bytes>;

// ---- Utility ----
// Convert a hex string to bytes.
[[nodiscard]] auto from_hex(std::string_view hex) -> std::optional<Bytes>;

// Convert bytes to hex string.
[[nodiscard]] auto to_hex(std::span<const std::byte> data) -> std::string;

// String literal to info bytes.
inline auto info_bytes(std::string_view s) -> std::span<const std::byte> {
    return std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()), s.size());
}

} // namespace era::crypto
