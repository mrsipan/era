# era

**A modern C++23 implementation of the [age](https://github.com/FiloSottile/age) file encryption format.**

`era` is a fast, static, drop-in compatible implementation of [age-encryption.org/v1](https://age-encryption.org/v1). It uses [libsodium](https://doc.libsodium.org/) for all cryptographic primitives and compiles to a single, dependency-free binary (statically linked against libsodium).

## Features

- **X25519** asymmetric encryption — `age1...` recipient strings
- **scrypt** passphrase-based encryption
- **ASCII armor** — PEM encoding per RFC 7468
- **Streaming encryption** — 64 KiB chunks, seekable
- **Multiple recipients** — encrypt to any number of keys
- **Fully interoperable** with the official Go `age` and `age-keygen`
- **Single binary** — works as both `era` and `era-keygen`
- **No heap allocations in the hot path** — modern C++ design with spans, `std::optional`, and `std::variant`

## Quick Start

### Build

```bash
# Requires: cmake >= 3.20, C++23 compiler (clang >= 17, gcc >= 14), libsodium
brew install cmake libsodium    # macOS
# or: apt install cmake libsodium-dev  # Debian/Ubuntu

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Usage

```bash
# Generate a new identity
era -k -o key.txt
# Public key: age1...

# Encrypt to a recipient
echo "Hello, World!" | era -r age1... -o secret.age

# Decrypt with an identity file
era -d -i key.txt -o decrypted.txt secret.age

# Encrypt with a passphrase
era -p -o secret.age < file.txt

# Decrypt with a passphrase
era -d -p -o file.txt secret.age

# ASCII armored output
era -a -r age1... -o secret.asc < file.txt
```

### `era-keygen` mode

When invoked as `era-keygen` (via symlink or rename), the binary automatically enters key generation mode:

```bash
ln -s build/era build/era-keygen
./build/era-keygen -o key.txt
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AGE_PASSPHRASE` | Passphrase for encryption/decryption (avoids interactive prompt) |

## CLI Reference

```
Usage: era [options] [input]

Options:
  -o, --output FILE     Write output to FILE (default: stdout, use - for stdout)
  -a, --armor           Use ASCII armor (PEM encoding)
  -d, --decrypt         Decrypt the input
  -p, --passphrase      Use passphrase-based encryption/decryption
  -r, --recipient REC   Encrypt for recipient (can be repeated)
  -i, --identity FILE   Identity file for decryption (can be repeated)
  -k, --keygen          Generate a new identity
  -h, --help            Show this help
  -V, --version         Show version

Input defaults to stdin. Output defaults to stdout.
```

## Architecture

```
era/
├── CMakeLists.txt              # Build configuration (C++23, libsodium)
├── src/
│   ├── main.cpp                # CLI entry point
│   └── era/
│       ├── base64.{hpp,cpp}    # RFC 4648 canonical & padded base64
│       ├── bech32.{hpp,cpp}    # BIP173 Bech32 (age key/recipient encoding)
│       ├── crypto.{hpp,cpp}    # libsodium wrappers for all primitives
│       ├── format.{hpp,cpp}    # age file format: header, streaming payload, armor
│       ├── identity.{hpp,cpp}  # Key generation, identity parsing/storage
│       ├── keys.{hpp,cpp}      # Public key derivation from secret keys
│       └── recipient.{hpp,cpp} # Recipient stanza encryption/decryption logic
└── test/                       # Test suite (disabled by default)
```

### Cryptographic Primitives

| Primitive | Implementation | Library |
|-----------|---------------|---------|
| X25519 | Curve25519 ECDH | libsodium `crypto_scalarmult` |
| ChaCha20-Poly1305 | AEAD encryption (RFC 7539) | libsodium `crypto_aead_chacha20poly1305_ietf` |
| HKDF-SHA-256 | Key derivation (RFC 5869) | Manual implementation over libsodium HMAC-SHA-256 |
| HMAC-SHA-256 | Message authentication (RFC 2104) | libsodium `crypto_auth_hmacsha256` |
| scrypt | Password-based KDF (RFC 7914) | libsodium `crypto_pwhash_scryptsalsa208sha256` |
| CSPRNG | Random number generation | libsodium `randombytes` |

### File Format

The age file format consists of a textual header followed by a binary payload:

```
age-encryption.org/v1
-> X25519 <base64-encoded-ephemeral-share>
<base64-encoded-wrapped-file-key>
--- <base64-encoded-header-mac>
<binary-payload: 16-byte-nonce || chunk₀ || chunk₁ || ...>
```

Each payload chunk is up to 64 KiB, encrypted with ChaCha20-Poly1305 using a nonce derived from the chunk index. The final chunk's nonce has the last byte set to `0x01` for authentication of end-of-stream.

## Compatibility

`era` implements the [age v1 specification](https://c2sp.org/age) and is tested against the official Go `age` tool:

| Test | Status |
|------|--------|
| `era` encrypt → `age` decrypt (raw) | ✅ |
| `age` encrypt → `era` decrypt (raw) | ✅ |
| `era` encrypt → `age` decrypt (armored) | ✅ |
| `age` encrypt → `era` decrypt (armored) | ✅ |
| `age-keygen` keys with `era` | ✅ |
| `era-keygen` keys with `age` | ✅ |
| Passphrase encryption/decryption | ✅ |
| Multiple recipients | ✅ |
| Empty files | ✅ |
| Binary files (null bytes, large files) | ✅ |

### Currently Supported Recipient Types

| Type | Status |
|------|--------|
| X25519 (`age1...`) | ✅ |
| scrypt passphrase | ✅ |

### Not Yet Implemented

| Type | Notes |
|------|-------|
| SSH Ed25519 (`ssh-ed25519`) | Requires Ed25519→X25519 conversion (libsodium has the primitives) |
| SSH RSA (`ssh-rsa`) | Requires RSA-OAEP (needs OpenSSL) |
| X-Wing (`mlkem768x25519`) | Post-quantum hybrid KEM |
| Plugin system | External identity/recipient plugins |

## License

MIT

## Credits

`era` is a clean-room implementation of the [age encryption format](https://github.com/FiloSottile/age) by Filippo Valsorda. It uses [libsodium](https://github.com/jedisct1/libsodium) for all cryptographic operations.
