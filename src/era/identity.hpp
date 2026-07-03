#pragma once
#include "era/crypto.hpp"
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace era::identity {

// An age identity (private key material).
struct X25519Identity {
    crypto::X25519Key secret_key;  // 32 bytes
};

// Identity can be X25519 or future types.
using Identity = std::variant<X25519Identity>;

// ---- Identity generation ----
// Generate a new X25519 identity.
[[nodiscard]] auto generate_x25519() -> X25519Identity;

// ---- Bech32 encoding/decoding ----
// Encode an X25519 identity to AGE-SECRET-KEY- Bech32 string.
[[nodiscard]] auto encode_x25519(const X25519Identity& id) -> std::string;

// Decode an AGE-SECRET-KEY- Bech32 string.
[[nodiscard]] auto decode_x25519(std::string_view encoded) -> std::optional<X25519Identity>;

// ---- File-based identity storage ----
// Parse an identity from an identity file (one per line, ignore comments/empty).
// Supported formats:
//   AGE-SECRET-KEY-1...
[[nodiscard]] auto parse_identity_file(std::string_view content) -> std::vector<Identity>;

// Parse a single identity string.
[[nodiscard]] auto parse_identity(std::string_view s) -> std::optional<Identity>;

} // namespace era::identity
