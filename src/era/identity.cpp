#include "era/identity.hpp"
#include "era/bech32.hpp"
#include <algorithm>
#include <cstring>
#include <sstream>

namespace era::identity {

auto generate_x25519() -> X25519Identity {
    auto kp = crypto::x25519_keygen();
    return X25519Identity{std::move(kp.secret_key)};
}

auto encode_x25519(const X25519Identity& id) -> std::string {
    std::span<const std::byte> key(id.secret_key.data(), id.secret_key.size());
    return bech32::encode("AGE-SECRET-KEY-", key);
}

auto decode_x25519(std::string_view encoded) -> std::optional<X25519Identity> {
    auto decoded = bech32::decode(encoded);
    if (!decoded) return std::nullopt;

    auto& [hrp, data] = *decoded;
    if (hrp != "age-secret-key-") return std::nullopt;
    if (data.size() != crypto::kX25519KeyLen) return std::nullopt;

    X25519Identity id;
    std::copy(data.begin(), data.end(), id.secret_key.begin());
    return id;
}

auto parse_identity_file(std::string_view content) -> std::vector<Identity> {
    std::vector<Identity> identities;
    std::istringstream iss{std::string(content)};
    std::string line;
    while (std::getline(iss, line)) {
        // Trim whitespace
        auto start = line.find_first_not_of(" \t\r");
        auto end = line.find_last_not_of(" \t\r");
        if (start == std::string::npos) continue; // empty line
        std::string trimmed = line.substr(start, end - start + 1);

        if (trimmed.empty() || trimmed[0] == '#') continue;

        auto id = parse_identity(trimmed);
        if (id) identities.push_back(std::move(*id));
    }
    return identities;
}

auto parse_identity(std::string_view s) -> std::optional<Identity> {
    // Try X25519 identity
    if (s.starts_with("AGE-SECRET-KEY-") || s.starts_with("age-secret-key-")) {
        auto id = decode_x25519(s);
        if (id) return Identity{std::move(*id)};
    }
    return std::nullopt;
}

} // namespace era::identity
