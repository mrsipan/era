#include "era/crypto.hpp"
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace era::crypto {

// Initialise libsodium (call once at startup)
namespace {
    struct SodiumInit {
        SodiumInit() {
            if (sodium_init() < 0) {
                throw std::runtime_error("libsodium initialization failed");
            }
        }
    };
    static SodiumInit _sodium_init;
}

// ---- Random ----

auto random(size_t n) -> Bytes {
    Bytes buf(n);
    randombytes_buf(buf.data(), n);
    return buf;
}

auto random_file_key() -> FileKey {
    FileKey key;
    randombytes_buf(key.data(), key.size());
    return key;
}

auto random_x25519_key() -> X25519Key {
    X25519Key key;
    randombytes_buf(key.data(), key.size());
    return key;
}

auto random_scrypt_salt() -> std::array<std::byte, kScryptSaltLen> {
    std::array<std::byte, kScryptSaltLen> salt;
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

auto random_payload_nonce() -> std::array<std::byte, kPayloadNonceLen> {
    std::array<std::byte, kPayloadNonceLen> nonce;
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

// ---- X25519 ----

auto x25519_keygen() -> X25519Keypair {
    X25519Keypair kp;
    crypto_box_keypair(
        reinterpret_cast<unsigned char*>(kp.public_key.data()),
        reinterpret_cast<unsigned char*>(kp.secret_key.data())
    );
    return kp;
}

auto x25519(std::span<const std::byte> scalar, std::span<const std::byte> point) -> std::optional<X25519Key> {
    if (scalar.size() != crypto_scalarmult_SCALARBYTES ||
        point.size() != crypto_scalarmult_BYTES) {
        return std::nullopt;
    }
    X25519Key result;
    int rc = crypto_scalarmult(
        reinterpret_cast<unsigned char*>(result.data()),
        reinterpret_cast<const unsigned char*>(scalar.data()),
        reinterpret_cast<const unsigned char*>(point.data())
    );
    if (rc != 0) return std::nullopt;
    return result;
}

// ---- ChaCha20-Poly1305 AEAD ----

auto chacha20_poly1305_encrypt(
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> plaintext
) -> std::optional<Bytes> {
    if (key.size() != crypto_aead_chacha20poly1305_IETF_KEYBYTES) return std::nullopt;
    if (nonce.size() != crypto_aead_chacha20poly1305_IETF_NPUBBYTES) return std::nullopt;

    Bytes ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long clen;

    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(ciphertext.data()),
        &clen,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        plaintext.size(),
        nullptr, 0,  // additional data
        nullptr,     // nsec (unused)
        reinterpret_cast<const unsigned char*>(nonce.data()),
        reinterpret_cast<const unsigned char*>(key.data())
    );
    if (rc != 0) return std::nullopt;
    ciphertext.resize(clen);
    return ciphertext;
}

auto chacha20_poly1305_decrypt(
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> ciphertext_with_tag
) -> std::optional<Bytes> {
    if (key.size() != crypto_aead_chacha20poly1305_IETF_KEYBYTES) return std::nullopt;
    if (nonce.size() != crypto_aead_chacha20poly1305_IETF_NPUBBYTES) return std::nullopt;
    if (ciphertext_with_tag.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) return std::nullopt;

    Bytes plaintext(ciphertext_with_tag.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long plen;

    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(plaintext.data()),
        &plen,
        nullptr,  // nsec (unused)
        reinterpret_cast<const unsigned char*>(ciphertext_with_tag.data()),
        ciphertext_with_tag.size(),
        nullptr, 0,  // additional data
        reinterpret_cast<const unsigned char*>(nonce.data()),
        reinterpret_cast<const unsigned char*>(key.data())
    );
    if (rc != 0) return std::nullopt;
    plaintext.resize(plen);
    return plaintext;
}

// ---- HKDF-SHA-256 ----

auto hkdf_sha256(
    std::span<const std::byte> ikm,
    std::span<const std::byte> salt,
    std::span<const std::byte> info,
    size_t length
) -> Bytes {
    // HKDF-Extract(salt, IKM) -> PRK = HMAC-SHA-256(salt, IKM)
    // If salt is empty, use a string of HashLen zeros (RFC 5869 Section 2.2)
    std::array<std::byte, 32> zero_salt{};
    std::span<const std::byte> actual_salt = salt;
    if (salt.empty()) {
        actual_salt = std::span<const std::byte>(zero_salt);
    }
    auto prk = hmac_sha256(actual_salt, ikm);

    // HKDF-Expand(PRK, info, L) -> OKM
    // T(0) = empty string
    // T(i) = HMAC-SHA-256(PRK, T(i-1) || info || i)  where i is a single byte
    Bytes okm;
    okm.reserve(length);
    Bytes t_prev;
    uint8_t counter = 1;

    while (okm.size() < length) {
        Bytes message;
        message.insert(message.end(), t_prev.begin(), t_prev.end());
        message.insert(message.end(), info.begin(), info.end());
        message.push_back(static_cast<std::byte>(counter++));

        auto t_cur = hmac_sha256(
            std::span<const std::byte>(prk.data(), prk.size()),
            message
        );
        t_prev.assign(t_cur.begin(), t_cur.end());

        size_t to_copy = std::min(t_cur.size(), length - okm.size());
        okm.insert(okm.end(), t_cur.begin(), t_cur.begin() + to_copy);
    }

    return okm;
}

// ---- HMAC-SHA-256 ----

auto hmac_sha256(
    std::span<const std::byte> key,
    std::span<const std::byte> data
) -> std::array<std::byte, 32> {
    std::array<std::byte, 32> mac;
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(
        &state,
        reinterpret_cast<const unsigned char*>(key.data()),
        key.size()
    );
    crypto_auth_hmacsha256_update(
        &state,
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size()
    );
    crypto_auth_hmacsha256_final(
        &state,
        reinterpret_cast<unsigned char*>(mac.data())
    );
    return mac;
}

// ---- scrypt ----

auto scrypt(
    std::string_view passphrase,
    std::span<const std::byte> salt,
    uint64_t N,
    size_t dklen
) -> std::optional<Bytes> {
    if (N < 2 || (N & (N - 1)) != 0) return std::nullopt; // N must be power of 2

    Bytes derived(dklen);

    int rc = crypto_pwhash_scryptsalsa208sha256_ll(
        reinterpret_cast<const uint8_t*>(passphrase.data()),
        passphrase.size(),
        reinterpret_cast<const unsigned char*>(salt.data()),
        salt.size(),
        N,
        8,   // r
        1,   // p
        reinterpret_cast<uint8_t*>(derived.data()),
        derived.size()
    );
    if (rc != 0) return std::nullopt;
    return derived;
}

// ---- Utility ----

auto from_hex(std::string_view hex) -> std::optional<Bytes> {
    if (hex.size() % 2 != 0) return std::nullopt;
    Bytes result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto high = [](char c) -> std::optional<uint8_t> {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return std::nullopt;
        };
        auto h = high(hex[i]);
        auto l = high(hex[i + 1]);
        if (!h || !l) return std::nullopt;
        result.push_back(static_cast<std::byte>((*h << 4) | *l));
    }
    return result;
}

auto to_hex(std::span<const std::byte> data) -> std::string {
    constexpr const char* hex_chars = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (auto b : data) {
        auto v = static_cast<uint8_t>(b);
        result.push_back(hex_chars[v >> 4]);
        result.push_back(hex_chars[v & 0x0F]);
    }
    return result;
}

} // namespace era::crypto
