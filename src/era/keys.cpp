#include "era/keys.hpp"
#include "era/bech32.hpp"
#include <sodium.h>

namespace era::keys {

auto derive_public(const crypto::X25519Key& secret_key) -> crypto::X25519Key {
    crypto::X25519Key pubkey;
    crypto_scalarmult_base(
        reinterpret_cast<unsigned char*>(pubkey.data()),
        reinterpret_cast<const unsigned char*>(secret_key.data())
    );
    return pubkey;
}

auto recipient_from_secret(const crypto::X25519Key& secret_key) -> std::string {
    auto pubkey = derive_public(secret_key);
    return bech32::encode("age", std::span<const std::byte>(pubkey.data(), pubkey.size()));
}

} // namespace era::keys
