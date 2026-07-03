#pragma once
#include "era/crypto.hpp"
#include "era/format.hpp"
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace era::recipient {

// ---- X25519 Recipient ----
// Parse an X25519 recipient from an "age1..." Bech32 string.
// Returns the 32-byte public key on success.
[[nodiscard]] auto parse_x25519_recipient(std::string_view s) -> std::optional<crypto::X25519Key>;

// Create an X25519 recipient stanza.
// Encrypts the file_key for the given recipient public key.
[[nodiscard]] auto encrypt_x25519(
    const crypto::FileKey& file_key,
    const crypto::X25519Key& recipient_pubkey
) -> std::optional<format::Stanza>;

// Decrypt the file key from an X25519 stanza using the identity.
[[nodiscard]] auto decrypt_x25519(
    const format::Stanza& stanza,
    const crypto::X25519Key& identity
) -> std::optional<crypto::FileKey>;

// ---- scrypt Recipient ----
// Create a scrypt recipient stanza for a passphrase.
// log_work_factor: base-2 log of scrypt N (e.g., 18 for N=262144).
[[nodiscard]] auto encrypt_scrypt(
    const crypto::FileKey& file_key,
    std::string_view passphrase,
    unsigned log_work_factor = 18
) -> std::optional<format::Stanza>;

// Decrypt the file key from a scrypt stanza using the passphrase.
[[nodiscard]] auto decrypt_scrypt(
    const format::Stanza& stanza,
    std::string_view passphrase
) -> std::optional<crypto::FileKey>;

// ---- General ----
// Parse a recipient string (age1... for X25519, or raw passphrase for scrypt...).
enum class RecipientType { X25519, Passphrase, Unknown };

struct ParsedRecipient {
    RecipientType type;
    std::variant<crypto::X25519Key, std::string> data; // pubkey or passphrase
};

[[nodiscard]] auto parse_recipient(std::string_view s) -> std::optional<ParsedRecipient>;

} // namespace era::recipient
