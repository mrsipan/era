#include "era/base64.hpp"
#include "era/crypto.hpp"
#include "era/format.hpp"
#include "era/identity.hpp"
#include "era/keys.hpp"
#include "era/recipient.hpp"

#include <sodium.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

// ---- Helpers ----

// Read entire file (or stdin) into bytes.
[[nodiscard]] auto read_input(const std::string& path) -> std::optional<era::crypto::Bytes> {
    if (path == "-" || path.empty()) {
        // Read from stdin
        era::crypto::Bytes data;
        char buf[65536];
        while (std::cin) {
            std::cin.read(buf, sizeof(buf));
            auto n = std::cin.gcount();
            if (n > 0) {
                data.insert(data.end(),
                    reinterpret_cast<const std::byte*>(buf),
                    reinterpret_cast<const std::byte*>(buf + n));
            }
        }
        if (std::cin.bad()) return std::nullopt;
        return data;
    }

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return std::nullopt;
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    era::crypto::Bytes data(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(data.data()), size);
    if (!file) return std::nullopt;
    return data;
}

// Write bytes to file (or stdout).
auto write_output(const std::string& path, std::span<const std::byte> data) -> bool {
    if (path == "-" || path.empty()) {
        std::cout.write(reinterpret_cast<const char*>(data.data()),
                        static_cast<std::streamsize>(data.size()));
        return !std::cout.bad();
    }

    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
    return !file.bad();
}

// Read passphrase from terminal or environment.
[[nodiscard]] auto read_passphrase() -> std::string {
    const char* env = std::getenv("AGE_PASSPHRASE");
    if (env) return std::string(env);

    // Try to read from /dev/tty for proper terminal handling
    std::string passphrase;
    if (FILE* tty = fopen("/dev/tty", "r")) {
        std::cerr << "Enter passphrase: " << std::flush;
        char buf[1024];
        if (fgets(buf, sizeof(buf), tty)) {
            passphrase = buf;
            // Remove trailing newline
            if (!passphrase.empty() && passphrase.back() == '\n') passphrase.pop_back();
            if (!passphrase.empty() && passphrase.back() == '\r') passphrase.pop_back();
        }
        fclose(tty);
        std::cerr << std::endl;
        return passphrase;
    }

    // Fallback: read from stdin with warning
    std::cerr << "Enter passphrase (warning: reading from stdin): " << std::flush;
    std::getline(std::cin, passphrase);
    std::cerr << std::endl;
    return passphrase;
}

// ---- Commands ----

int cmd_keygen(const std::string& output_path) {
    auto id = era::identity::generate_x25519();
    auto encoded = era::identity::encode_x25519(id);
    auto recipient = era::keys::recipient_from_secret(id.secret_key);

    // Output format: # created: date\n# recipient: age1...\nAGE-SECRET-KEY-1...
    std::string output;
    output += "# recipient: ";
    output += recipient;
    output += '\n';
    output += encoded;
    output += '\n';

    if (output_path.empty() || output_path == "-") {
        std::cout << output;
        std::cout.flush();
    } else {
        std::ofstream file(output_path);
        if (!file) {
            std::cerr << "era: error writing to " << output_path << ": " << std::strerror(errno) << '\n';
            return 1;
        }
        file << output;
    }

    std::cerr << "Public key: " << recipient << '\n';
    return 0;
}

int cmd_encrypt(
    const std::vector<std::string>& recipients,
    bool use_passphrase,
    bool armor,
    const std::string& input_path,
    const std::string& output_path
) {
    if (recipients.empty() && !use_passphrase) {
        std::cerr << "era: error: missing recipients (use -r or -p)\n";
        return 1;
    }

    // Read input
    auto plaintext = read_input(input_path);
    if (!plaintext) {
        std::cerr << "era: error reading input: " << std::strerror(errno) << '\n';
        return 1;
    }

    // Parse recipients
    std::vector<era::recipient::ParsedRecipient> parsed_recipients;
    for (const auto& r : recipients) {
        auto parsed = era::recipient::parse_recipient(r);
        if (!parsed) {
            std::cerr << "era: error: invalid recipient: " << r << '\n';
            return 1;
        }
        parsed_recipients.push_back(std::move(*parsed));
    }

    // If passphrase is used, check it's the only recipient type
    if (use_passphrase && !parsed_recipients.empty()) {
        std::cerr << "era: error: scrypt passphrase cannot be mixed with other recipients\n";
        return 1;
    }

    // Generate file key
    auto file_key = era::crypto::random_file_key();

    // Build header
    era::format::Header header;

    for (const auto& pr : parsed_recipients) {
        if (pr.type == era::recipient::RecipientType::X25519) {
            auto& pubkey = std::get<era::crypto::X25519Key>(pr.data);
            auto stanza = era::recipient::encrypt_x25519(file_key, pubkey);
            if (!stanza) {
                std::cerr << "era: error: failed to encrypt for X25519 recipient\n";
                return 1;
            }
            header.stanzas.push_back(std::move(*stanza));
        } else if (pr.type == era::recipient::RecipientType::Passphrase) {
            auto& pass = std::get<std::string>(pr.data);
            auto stanza = era::recipient::encrypt_scrypt(file_key, pass);
            if (!stanza) {
                std::cerr << "era: error: failed to encrypt for passphrase\n";
                return 1;
            }
            header.stanzas.push_back(std::move(*stanza));
        }
    }

    if (use_passphrase) {
        auto passphrase = read_passphrase();
        auto stanza = era::recipient::encrypt_scrypt(file_key, passphrase);
        if (!stanza) {
            std::cerr << "era: error: failed to encrypt for passphrase\n";
            return 1;
        }
        header.stanzas.push_back(std::move(*stanza));
    }

    // Serialize header (version line + stanzas + "--- ")
    std::string header_prefix = era::format::serialize_header(header);

    // Compute MAC: over everything up to "---" (excluding space after dashes)
    // The header_prefix ends with "--- " so strip the trailing space
    std::string header_up_to_dashes = header_prefix.substr(0, header_prefix.size() - 1);  // strip trailing space
    auto mac = era::format::compute_header_mac(header_up_to_dashes, file_key);

    // Full header: header_prefix + base64(mac) + "\n"
    std::string final_header = header_prefix
        + era::base64::encode(std::span<const std::byte>(mac.data(), mac.size()))
        + "\n";

    // Encrypt payload
    auto nonce = era::crypto::random_payload_nonce();
    auto encrypted_payload = era::format::encrypt_payload(file_key, nonce, *plaintext);
    if (!encrypted_payload) {
        std::cerr << "era: error: payload encryption failed\n";
        return 1;
    }

    // Combine header + payload
    era::crypto::Bytes output;
    output.insert(output.end(),
        reinterpret_cast<const std::byte*>(final_header.data()),
        reinterpret_cast<const std::byte*>(final_header.data() + final_header.size()));
    output.insert(output.end(), encrypted_payload->begin(), encrypted_payload->end());

    // Apply armor if requested
    if (armor) {
        std::string armored = era::format::armor(output);
        era::crypto::Bytes armored_bytes(
            reinterpret_cast<const std::byte*>(armored.data()),
            reinterpret_cast<const std::byte*>(armored.data() + armored.size()));
        if (!write_output(output_path, armored_bytes)) {
            std::cerr << "era: error writing output: " << std::strerror(errno) << '\n';
            return 1;
        }
    } else {
        if (!write_output(output_path, output)) {
            std::cerr << "era: error writing output: " << std::strerror(errno) << '\n';
            return 1;
        }
    }

    std::cerr << "era: encrypted successfully\n";
    return 0;
}

int cmd_decrypt(
    const std::vector<std::string>& identity_paths,
    bool use_passphrase,
    const std::string& input_path,
    const std::string& output_path
) {
    // Read input
    auto data = read_input(input_path);
    if (!data) {
        std::cerr << "era: error reading input: " << std::strerror(errno) << '\n';
        return 1;
    }

    // Try dearmoring first
    std::string data_str(reinterpret_cast<const char*>(data->data()), data->size());
    era::crypto::Bytes raw_data;
    if (auto dearmored = era::format::dearmor(data_str)) {
        raw_data = std::move(*dearmored);
    } else {
        raw_data = std::move(*data);
    }

    // Split header from payload: find the first occurrence of "\n--- "
    std::string raw_str(reinterpret_cast<const char*>(raw_data.data()), raw_data.size());
    auto header_end = raw_str.find("\n--- ");
    if (header_end == std::string::npos) {
        std::cerr << "era: error: invalid age file format\n";
        return 1;
    }

    // Find end of MAC line
    auto mac_end = raw_str.find('\n', header_end + 1);
    if (mac_end == std::string::npos) {
        std::cerr << "era: error: invalid age file format\n";
        return 1;
    }

    std::string_view header_text(raw_str.data(), mac_end + 1);
    std::span<const std::byte> payload_bytes(
        raw_data.data() + mac_end + 1,
        raw_data.size() - mac_end - 1
    );

    // Parse header
    auto header = era::format::parse_header(header_text);
    if (!header) {
        std::cerr << "era: error: failed to parse age header\n";
        return 1;
    }

    // Load identities
    std::vector<era::identity::Identity> identities;
    for (const auto& path : identity_paths) {
        std::string content;
        if (path == "-") {
            std::string line;
            while (std::getline(std::cin, line)) content += line + '\n';
        } else {
            std::ifstream file(path);
            if (!file) {
                std::cerr << "era: warning: cannot read identity file: " << path << '\n';
                continue;
            }
            std::ostringstream oss;
            oss << file.rdbuf();
            content = oss.str();
        }
        auto ids = era::identity::parse_identity_file(content);
        identities.insert(identities.end(), ids.begin(), ids.end());
    }

    // Try to decrypt file key
    std::optional<era::crypto::FileKey> file_key;

    // Try scrypt first if passphrase is provided
    if (use_passphrase) {
        for (const auto& stanza : header->stanzas) {
            if (stanza.type == era::format::StanzaType::Scrypt) {
                auto passphrase = read_passphrase();
                auto fk = era::recipient::decrypt_scrypt(stanza, passphrase);
                if (fk) {
                    file_key = std::move(*fk);
                    break;
                }
                // Wrong passphrase - continue to try other methods
                std::cerr << "era: error: bad passphrase\n";
                return 1;
            }
        }
    }

    // Try X25519 identities
    if (!file_key) {
        for (const auto& id : identities) {
            if (auto* xid = std::get_if<era::identity::X25519Identity>(&id)) {
                for (const auto& stanza : header->stanzas) {
                    if (stanza.type == era::format::StanzaType::X25519) {
                        auto fk = era::recipient::decrypt_x25519(stanza, xid->secret_key);
                        if (fk) {
                            file_key = std::move(*fk);
                            break;
                        }
                    }
                }
                if (file_key) break;
            }
        }
    }

    if (!file_key) {
        std::cerr << "era: error: no identity matched any recipient\n";
        return 1;
    }

    // Decrypt payload
    auto plaintext = era::format::decrypt_payload(*file_key, payload_bytes);
    if (!plaintext) {
        std::cerr << "era: error: payload decryption failed\n";
        return 1;
    }

    if (!write_output(output_path, *plaintext)) {
        std::cerr << "era: error writing output: " << std::strerror(errno) << '\n';
        return 1;
    }

    std::cerr << "era: decrypted successfully\n";
    return 0;
}

// ---- Main ----

void print_usage(std::string_view prog) {
    std::cerr << "Usage: " << prog << " [options] [input]\n\n";
    std::cerr << "Options:\n";
    std::cerr << "  -o, --output FILE     Write output to FILE (default: stdout)\n";
    std::cerr << "  -a, --armor           Use ASCII armor (PEM encoding)\n";
    std::cerr << "  -d, --decrypt         Decrypt the input\n";
    std::cerr << "  -p, --passphrase      Use passphrase-based encryption/decryption\n";
    std::cerr << "  -r, --recipient REC   Encrypt for recipient (can be repeated)\n";
    std::cerr << "  -i, --identity FILE   Identity file for decryption (can be repeated)\n";
    std::cerr << "  -k, --keygen          Generate a new identity\n";
    std::cerr << "  -h, --help            Show this help\n";
    std::cerr << "  -V, --version         Show version\n\n";
    std::cerr << "Input defaults to stdin. Output defaults to stdout.\n";
}

int main(int argc, char* argv[]) {
    std::string_view prog = argv[0];

    // Detect if invoked as era-keygen
    if (prog.ends_with("era-keygen") || prog.find("era-keygen") != std::string_view::npos) {
        std::string output;
        for (int i = 1; i < argc; ++i) {
            std::string_view arg = argv[i];
            if (arg == "-o" || arg == "--output") {
                if (i + 1 < argc) output = argv[++i];
            } else if (arg == "-h" || arg == "--help") {
                std::cerr << "Usage: era-keygen [-o OUTPUT]\n";
                return 0;
            }
        }
        if (sodium_init() < 0) {
            std::cerr << "era: error: libsodium initialization failed\n";
            return 1;
        }
        return cmd_keygen(output);
    }

    // Parse arguments
    std::vector<std::string> args(argv + 1, argv + argc);

    bool decrypt = false;
    bool armor = false;
    bool passphrase = false;
    bool keygen = false;
    std::string output_path;
    std::string input_path;
    std::vector<std::string> recipients;
    std::vector<std::string> identities;

    for (size_t i = 0; i < args.size(); ++i) {
        std::string_view arg = args[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(prog);
            return 0;
        }
        if (arg == "-V" || arg == "--version") {
            std::cerr << "era 0.1.0\n";
            return 0;
        }
        if (arg == "-d" || arg == "--decrypt") {
            decrypt = true;
        } else if (arg == "-a" || arg == "--armor") {
            armor = true;
        } else if (arg == "-p" || arg == "--passphrase") {
            passphrase = true;
        } else if (arg == "-k" || arg == "--keygen") {
            keygen = true;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= args.size()) {
                std::cerr << "era: error: -o requires an argument\n";
                return 1;
            }
            output_path = args[++i];
        } else if (arg == "-r" || arg == "--recipient") {
            if (i + 1 >= args.size()) {
                std::cerr << "era: error: -r requires an argument\n";
                return 1;
            }
            recipients.push_back(args[++i]);
        } else if (arg == "-i" || arg == "--identity") {
            if (i + 1 >= args.size()) {
                std::cerr << "era: error: -i requires an argument\n";
                return 1;
            }
            identities.push_back(args[++i]);
        } else if (arg.starts_with("-")) {
            std::cerr << "era: error: unknown option: " << arg << '\n';
            return 1;
        } else {
            if (input_path.empty()) {
                input_path = arg;
            } else {
                std::cerr << "era: error: multiple input files specified\n";
                return 1;
            }
        }
    }

    // Initialize libsodium (already done via static init in crypto.cpp,
    // but calling sodium_init again is harmless)
    if (sodium_init() < 0) {
        std::cerr << "era: error: libsodium initialization failed\n";
        return 1;
    }

    if (keygen) {
        return cmd_keygen(output_path);
    }

    if (decrypt) {
        return cmd_decrypt(identities, passphrase, input_path, output_path);
    }

    return cmd_encrypt(recipients, passphrase, armor, input_path, output_path);
}
