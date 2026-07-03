#include "era/recipient.hpp"
#include "era/base64.hpp"
#include "era/bech32.hpp"
#include <sodium.h>
#include <algorithm>
#include <cstring>

namespace era::recipient {

// ---- X25519 Recipient ----

auto parse_x25519_recipient(std::string_view s) -> std::optional<crypto::X25519Key> {
    auto decoded = bech32::decode(s);
    if (!decoded) return std::nullopt;

    auto& [hrp, data] = *decoded;
    if (hrp != "age") return std::nullopt;
    if (data.size() != crypto::kX25519KeyLen) return std::nullopt;

    crypto::X25519Key pubkey;
    std::copy(data.begin(), data.end(), pubkey.begin());
    return pubkey;
}

auto encrypt_x25519(
    const crypto::FileKey& file_key,
    const crypto::X25519Key& recipient_pubkey
) -> std::optional<format::Stanza> {
    // Generate ephemeral keypair
    auto ephemeral = crypto::x25519_keygen();
    // ephemeral.public_key is already the ephemeral share

    // shared secret = X25519(ephemeral secret, recipient)
    auto shared_secret = crypto::x25519(
        std::span<const std::byte>(ephemeral.secret_key.data(), ephemeral.secret_key.size()),
        std::span<const std::byte>(recipient_pubkey.data(), recipient_pubkey.size())
    );
    if (!shared_secret) return std::nullopt;

    // Check shared secret is not all zeros
    bool all_zero = std::all_of(shared_secret->begin(), shared_secret->end(),
        [](std::byte b) { return b == std::byte{0}; });
    if (all_zero) return std::nullopt;

    // salt = ephemeral share || recipient
    crypto::Bytes salt;
    salt.insert(salt.end(), ephemeral.public_key.begin(), ephemeral.public_key.end());
    salt.insert(salt.end(), recipient_pubkey.begin(), recipient_pubkey.end());

    // wrap key = HKDF-SHA-256(ikm = shared secret, salt, info = "age-encryption.org/v1/X25519")
    auto wrap_key = crypto::hkdf_sha256(
        std::span<const std::byte>(shared_secret->data(), shared_secret->size()),
        salt,
        crypto::info_bytes("age-encryption.org/v1/X25519")
    );

    // body = ChaCha20-Poly1305(key = wrap key, plaintext = file key)
    // nonce fixed as 12 zero bytes
    std::array<std::byte, 12> nonce{};
    auto body = crypto::chacha20_poly1305_encrypt(
        wrap_key,
        nonce,
        std::span<const std::byte>(file_key.data(), file_key.size())
    );
    if (!body) return std::nullopt;

    format::Stanza stanza;
    stanza.type = format::StanzaType::X25519;
    stanza.args = {"X25519", base64::encode(std::span<const std::byte>(ephemeral.public_key.data(), ephemeral.public_key.size()))};
    stanza.body = std::move(*body);

    return stanza;
}

auto decrypt_x25519(
    const format::Stanza& stanza,
    const crypto::X25519Key& identity
) -> std::optional<crypto::FileKey> {
    if (stanza.type != format::StanzaType::X25519) return std::nullopt;
    if (stanza.args.size() != 2) return std::nullopt;
    if (stanza.body.size() != 32) return std::nullopt; // file key (16) + tag (16)

    // Parse ephemeral share
    auto ephemeral_share = base64::decode(stanza.args[1]);
    if (!ephemeral_share || ephemeral_share->size() != crypto::kX25519KeyLen) return std::nullopt;

    crypto::X25519Key eph_pub;
    std::copy(ephemeral_share->begin(), ephemeral_share->end(), eph_pub.begin());

    // shared secret = X25519(identity, ephemeral share)
    auto shared_secret = crypto::x25519(
        std::span<const std::byte>(identity.data(), identity.size()),
        std::span<const std::byte>(eph_pub.data(), eph_pub.size())
    );
    if (!shared_secret) return std::nullopt;

    // Check all zeros
    bool all_zero = std::all_of(shared_secret->begin(), shared_secret->end(),
        [](std::byte b) { return b == std::byte{0}; });
    if (all_zero) return std::nullopt;

    // Compute recipient public key from identity
    crypto::X25519Key recipient_pub;
    crypto_scalarmult_base(
        reinterpret_cast<unsigned char*>(recipient_pub.data()),
        reinterpret_cast<const unsigned char*>(identity.data())
    );

    // salt = ephemeral share || recipient
    crypto::Bytes salt;
    salt.insert(salt.end(), eph_pub.begin(), eph_pub.end());
    salt.insert(salt.end(), recipient_pub.begin(), recipient_pub.end());

    // wrap key
    auto wrap_key = crypto::hkdf_sha256(
        std::span<const std::byte>(shared_secret->data(), shared_secret->size()),
        salt,
        crypto::info_bytes("age-encryption.org/v1/X25519")
    );

    // decrypt
    std::array<std::byte, 12> nonce{};
    auto decrypted = crypto::chacha20_poly1305_decrypt(wrap_key, nonce, stanza.body);
    if (!decrypted || decrypted->size() != crypto::kFileKeyLen) return std::nullopt;

    crypto::FileKey file_key;
    std::copy(decrypted->begin(), decrypted->end(), file_key.begin());
    return file_key;
}

// ---- scrypt Recipient ----

auto encrypt_scrypt(
    const crypto::FileKey& file_key,
    std::string_view passphrase,
    unsigned log_work_factor
) -> std::optional<format::Stanza> {
    if (log_work_factor < 1 || log_work_factor > 30) return std::nullopt;

    // Generate 16-byte salt
    auto salt = crypto::random_scrypt_salt();

    // Full salt = "age-encryption.org/v1/scrypt" || salt
    std::string salt_prefix = "age-encryption.org/v1/scrypt";
    crypto::Bytes full_salt;
    full_salt.insert(full_salt.end(),
        reinterpret_cast<const std::byte*>(salt_prefix.data()),
        reinterpret_cast<const std::byte*>(salt_prefix.data() + salt_prefix.size()));
    full_salt.insert(full_salt.end(), salt.begin(), salt.end());

    uint64_t N = uint64_t{1} << log_work_factor;

    // wrap key = scrypt(N, r=8, p=1, salt=full_salt, passphrase)
    auto wrap_key = crypto::scrypt(passphrase, full_salt, N, 32);
    if (!wrap_key) return std::nullopt;

    // body = ChaCha20-Poly1305(key=wrap_key, plaintext=file_key, nonce=0*12)
    std::array<std::byte, 12> nonce{};
    auto body = crypto::chacha20_poly1305_encrypt(
        *wrap_key,
        nonce,
        std::span<const std::byte>(file_key.data(), file_key.size())
    );
    if (!body) return std::nullopt;

    format::Stanza stanza;
    stanza.type = format::StanzaType::Scrypt;
    stanza.args = {
        "scrypt",
        base64::encode(std::span<const std::byte>(salt.data(), salt.size())),
        std::to_string(log_work_factor)
    };
    stanza.body = std::move(*body);

    return stanza;
}

auto decrypt_scrypt(
    const format::Stanza& stanza,
    std::string_view passphrase
) -> std::optional<crypto::FileKey> {
    if (stanza.type != format::StanzaType::Scrypt) return std::nullopt;
    if (stanza.args.size() != 3) return std::nullopt;
    if (stanza.body.size() != 32) return std::nullopt;

    // Parse salt
    auto salt_bytes = base64::decode(stanza.args[1]);
    if (!salt_bytes || salt_bytes->size() != crypto::kScryptSaltLen) return std::nullopt;

    // Parse log work factor
    uint64_t log_work_factor;
    try {
        int lf = std::stoi(stanza.args[2]);
        if (lf < 1) return std::nullopt;
        log_work_factor = static_cast<uint64_t>(lf);
    } catch (...) {
        return std::nullopt;
    }

    // Check no leading zeros
    if (stanza.args[2].size() > 1 && stanza.args[2][0] == '0') return std::nullopt;

    uint64_t N = uint64_t{1} << log_work_factor;

    // Full salt
    std::string salt_prefix = "age-encryption.org/v1/scrypt";
    crypto::Bytes full_salt;
    full_salt.insert(full_salt.end(),
        reinterpret_cast<const std::byte*>(salt_prefix.data()),
        reinterpret_cast<const std::byte*>(salt_prefix.data() + salt_prefix.size()));
    full_salt.insert(full_salt.end(), salt_bytes->begin(), salt_bytes->end());

    // derive wrap key
    auto wrap_key = crypto::scrypt(passphrase, full_salt, N, 32);
    if (!wrap_key) return std::nullopt;

    // decrypt
    std::array<std::byte, 12> nonce{};
    auto decrypted = crypto::chacha20_poly1305_decrypt(*wrap_key, nonce, stanza.body);
    if (!decrypted || decrypted->size() != crypto::kFileKeyLen) return std::nullopt;

    crypto::FileKey file_key;
    std::copy(decrypted->begin(), decrypted->end(), file_key.begin());
    return file_key;
}

// ---- General ----

auto parse_recipient(std::string_view s) -> std::optional<ParsedRecipient> {
    // Try X25519
    if (s.starts_with("age1") && !s.starts_with("age1pq") && !s.starts_with("age1tag")) {
        auto key = parse_x25519_recipient(s);
        if (key) return std::optional<ParsedRecipient>(ParsedRecipient{RecipientType::X25519, std::move(*key)});
        return std::nullopt;
    }

    // Treat as passphrase (for encryption)
    // In age CLI, passphrase is typically provided via -p flag or terminal,
    // but we support it here as well for API usage.
    return std::optional<ParsedRecipient>(ParsedRecipient{RecipientType::Passphrase, std::string(s)});
}

} // namespace era::recipient
