#include "era/format.hpp"
#include "era/base64.hpp"
#include "era/crypto.hpp"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace era::format {
namespace {

// Split string by whitespace
auto split_args(const std::string& line) -> std::vector<std::string> {
    std::vector<std::string> args;
    std::istringstream iss(line);
    std::string arg;
    while (iss >> arg) args.push_back(arg);
    return args;
}

// Word-wrap a base64 string to 64 columns
auto wrap64(const std::string& b64) -> std::string {
    std::string result;
    result.reserve(b64.size() + b64.size() / 64 + 1);
    for (size_t i = 0; i < b64.size(); i += 64) {
        if (i > 0) result += '\n';
        result += b64.substr(i, 64);
    }
    return result;
}

} // anonymous namespace

auto parse_header(std::string_view header_text) -> std::optional<Header> {
    if (!header_text.starts_with(kVersionLine)) return std::nullopt;

    Header header;
    size_t pos = kVersionLine.size();
    std::string header_for_mac(header_text.substr(0, pos));

    while (pos < header_text.size()) {
        // Find next line
        auto nl = header_text.find('\n', pos);
        if (nl == std::string_view::npos) return std::nullopt;
        std::string_view line = header_text.substr(pos, nl - pos + 1);
        pos = nl + 1;

        if (line.starts_with("---")) {
            // MAC line - end of header
            // Format: "--- " + base64
            if (line.size() < 5 || line[3] != ' ') return std::nullopt;
            std::string_view mac_b64 = line.substr(4);
            // Remove trailing newline
            if (mac_b64.ends_with("\n")) mac_b64 = mac_b64.substr(0, mac_b64.size() - 1);

            auto mac_bytes = base64::decode(mac_b64);
            if (!mac_bytes || mac_bytes->size() != crypto::kHkdfOutputLen) return std::nullopt;
            std::copy(mac_bytes->begin(), mac_bytes->end(), header.mac.begin());
            return header;
        }

        if (line.starts_with("->")) {
            // Stanza
            Stanza stanza;
            stanza.raw = std::string(line);

            // Parse argument line
            if (line.size() < 4 || line[2] != ' ') return std::nullopt;
            std::string arg_line(line.substr(3, line.size() - 4)); // remove "-> " and "\n"
            stanza.args = split_args(arg_line);
            if (stanza.args.empty()) return std::nullopt;

            // Determine type
            if (stanza.args[0] == "X25519") stanza.type = StanzaType::X25519;
            else if (stanza.args[0] == "scrypt") stanza.type = StanzaType::Scrypt;
            else stanza.type = StanzaType::Unknown;

            // Read body lines (base64, 64 columns, last line shorter)
            std::string body_b64;
            while (pos < header_text.size()) {
                nl = header_text.find('\n', pos);
                if (nl == std::string_view::npos) return std::nullopt;
                std::string_view body_line = header_text.substr(pos, nl - pos + 1);
                pos = nl + 1;

                stanza.raw += std::string(body_line);

                // Remove trailing newline
                std::string_view content = body_line.substr(0, body_line.size() - 1);

                if (content.size() < 64) {
                    // Last line of body
                    body_b64 += content;
                    break;
                }
                body_b64 += content;
            }

            auto body = base64::decode(body_b64);
            if (!body) return std::nullopt;
            stanza.body = std::move(*body);
            header.stanzas.push_back(std::move(stanza));
        } else {
            return std::nullopt; // unexpected line
        }
    }

    return std::nullopt; // no MAC line found
}

auto serialize_header(const Header& header) -> std::string {
    std::string result(kVersionLine);

    for (const auto& stanza : header.stanzas) {
        result += "->";
        for (const auto& arg : stanza.args) {
            result += ' ';
            result += arg;
        }
        result += '\n';

        std::string body_b64 = base64::encode(stanza.body);
        result += wrap64(body_b64);
        result += '\n';
    }

    // End with "--- " prefix (MAC to be appended by caller)
    result += "--- ";
    return result;
}

auto compute_header_mac(std::string_view header_up_to_dashes, const crypto::FileKey& file_key) -> std::array<std::byte, 32> {
    // HMAC key = HKDF-SHA-256(ikm = file key, salt = empty, info = "header")
    auto hmac_key = crypto::hkdf_sha256(
        std::span<const std::byte>(file_key.data(), file_key.size()),
        std::span<const std::byte>{},  // empty salt
        crypto::info_bytes("header"),
        32
    );

    return crypto::hmac_sha256(hmac_key, crypto::info_bytes(header_up_to_dashes));
}

auto encrypt_payload(
    const crypto::FileKey& file_key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> plaintext
) -> std::optional<crypto::Bytes> {
    if (nonce.size() != crypto::kPayloadNonceLen) return std::nullopt;

    // payload key = HKDF-SHA-256(ikm = file key, salt = nonce, info = "payload")
    auto payload_key = crypto::hkdf_sha256(
        std::span<const std::byte>(file_key.data(), file_key.size()),
        nonce,
        crypto::info_bytes("payload")
    );
    if (payload_key.size() != crypto::kChachaKeyLen) return std::nullopt;

    crypto::Bytes result;
    result.reserve(nonce.size() + plaintext.size() + 1024); // rough estimate
    result.insert(result.end(), nonce.begin(), nonce.end());

    size_t total_chunks = (plaintext.size() + kChunkSize - 1) / kChunkSize;
    if (plaintext.empty()) total_chunks = 1; // empty file gets one empty final chunk

    for (size_t chunk_idx = 0; chunk_idx < total_chunks; ++chunk_idx) {
        size_t offset = chunk_idx * kChunkSize;
        size_t chunk_len = std::min(kChunkSize, plaintext.size() - offset);
        bool is_last = (chunk_idx == total_chunks - 1);

        // Nonce: big-endian chunk counter (11 bytes) + 0x01 for final, 0x00 otherwise
        std::array<std::byte, 12> chunk_nonce{};
        // Big endian chunk counter
        uint64_t counter = chunk_idx;
        for (int i = 10; i >= 3; --i) {
            chunk_nonce[i] = static_cast<std::byte>(counter & 0xFF);
            counter >>= 8;
        }
        chunk_nonce[11] = static_cast<std::byte>(is_last ? 0x01 : 0x00);

        auto chunk_plain = plaintext.subspan(offset, chunk_len);
        auto encrypted = crypto::chacha20_poly1305_encrypt(
            payload_key,
            chunk_nonce,
            chunk_plain
        );
        if (!encrypted) return std::nullopt;
        result.insert(result.end(), encrypted->begin(), encrypted->end());
    }

    return result;
}

auto decrypt_payload(
    const crypto::FileKey& file_key,
    std::span<const std::byte> payload_with_nonce
) -> std::optional<crypto::Bytes> {
    if (payload_with_nonce.size() < crypto::kPayloadNonceLen) return std::nullopt;

    auto nonce = payload_with_nonce.subspan(0, crypto::kPayloadNonceLen);
    auto encrypted = payload_with_nonce.subspan(crypto::kPayloadNonceLen);

    // payload key = HKDF-SHA-256(ikm = file key, salt = nonce, info = "payload")
    auto payload_key = crypto::hkdf_sha256(
        std::span<const std::byte>(file_key.data(), file_key.size()),
        nonce,
        crypto::info_bytes("payload")
    );

    crypto::Bytes plaintext;
    size_t pos = 0;
    size_t chunk_idx = 0;

    constexpr size_t kChunkOverhead = crypto::kChachaTagLen; // 16-byte tag per chunk
    constexpr size_t kEncryptedChunkSize = kChunkSize + kChunkOverhead;

    while (pos < encrypted.size()) {
        // Each chunk: plaintext (up to 64K) + 16-byte tag
        size_t remaining = encrypted.size() - pos;
        if (remaining < kChunkOverhead) return std::nullopt; // incomplete chunk

        size_t chunk_len = std::min(kEncryptedChunkSize, remaining);
        bool is_last = (pos + chunk_len >= encrypted.size());

        // Nonce
        std::array<std::byte, 12> chunk_nonce{};
        uint64_t counter = chunk_idx;
        for (int i = 10; i >= 3; --i) {
            chunk_nonce[i] = static_cast<std::byte>(counter & 0xFF);
            counter >>= 8;
        }
        chunk_nonce[11] = static_cast<std::byte>(is_last ? 0x01 : 0x00);

        auto decrypted = crypto::chacha20_poly1305_decrypt(
            payload_key,
            chunk_nonce,
            encrypted.subspan(pos, chunk_len)
        );
        if (!decrypted) return std::nullopt;
        plaintext.insert(plaintext.end(), decrypted->begin(), decrypted->end());

        pos += chunk_len;
        ++chunk_idx;

        if (is_last) break;
    }

    return plaintext;
}

auto armor(std::span<const std::byte> data) -> std::string {
    std::string b64 = base64::encode_padded(data);

    std::string result;
    result.reserve(b64.size() + b64.size() / 64 + 32);
    result += "-----BEGIN AGE ENCRYPTED FILE-----\n";

    for (size_t i = 0; i < b64.size(); i += 64) {
        result += b64.substr(i, 64);
        result += '\n';
    }

    result += "-----END AGE ENCRYPTED FILE-----\n";
    return result;
}

auto dearmor(std::string_view pem) -> std::optional<crypto::Bytes> {
    // Strip leading/trailing whitespace
    auto start = pem.find_first_not_of(" \t\r\n");
    auto end = pem.find_last_not_of(" \t\r\n");
    if (start == std::string_view::npos) return std::nullopt;
    pem = pem.substr(start, end - start + 1);

    std::string_view begin_marker = "-----BEGIN AGE ENCRYPTED FILE-----";
    std::string_view end_marker = "-----END AGE ENCRYPTED FILE-----";

    auto begin_pos = pem.find(begin_marker);
    if (begin_pos == std::string_view::npos) return std::nullopt;

    auto end_pos = pem.rfind(end_marker);
    if (end_pos == std::string_view::npos) return std::nullopt;

    size_t data_start = begin_pos + begin_marker.size();
    // Skip newline after marker
    if (data_start < pem.size() && pem[data_start] == '\r') ++data_start;
    if (data_start < pem.size() && pem[data_start] == '\n') ++data_start;

    std::string_view b64_data = pem.substr(data_start, end_pos - data_start);

    // Remove all whitespace from base64 data
    std::string clean_b64;
    clean_b64.reserve(b64_data.size());
    for (char c : b64_data) {
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            clean_b64 += c;
        }
    }

    return base64::decode_padded(clean_b64);
}

} // namespace era::format
