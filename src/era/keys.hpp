#pragma once
#include "era/crypto.hpp"
#include <string>
#include <string_view>

namespace era::keys {

// Derive an X25519 public key from a secret key.
[[nodiscard]] auto derive_public(const crypto::X25519Key& secret_key) -> crypto::X25519Key;

// Derive an age recipient string (age1...) from a secret key.
[[nodiscard]] auto recipient_from_secret(const crypto::X25519Key& secret_key) -> std::string;

} // namespace era::keys
