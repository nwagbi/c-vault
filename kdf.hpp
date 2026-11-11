#pragma once

#include <cstddef>
#include <string>

namespace cvalt {

// Length of the symmetric key produced by the KDF (XChaCha20-Poly1305 key size).
inline constexpr std::size_t KeyBytes = 32;

// Derive a key from a password with Argon2id13.
// `saltLen` must equal crypto_pwhash_SALTBYTES (16).
// Returns false and sets `error` on failure.
bool deriveKey(const std::string& password,
               const unsigned char* salt,
               std::size_t saltLen,
               unsigned long long opslimit,
               std::size_t memlimit,
               unsigned char* key,
               std::string& error);

}  // namespace cvalt
