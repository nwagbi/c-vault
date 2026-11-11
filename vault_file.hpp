#pragma once

#include <span>
#include <string>
#include <vector>

namespace cvalt {

using Bytes = std::vector<unsigned char>;

// Encrypt `plaintext` with a password and write a self-contained vault file.
//
// Layout (little-endian):
//   magic "CVLT" (4) | version (1) | kdf id (1) |
//   opslimit u32 (4) | memlimit u32 (4) | salt (16) | nonce (24) |
//   ciphertext + Poly1305 tag
//
// The whole header is passed as associated data, so touching the salt, nonce,
// version or KDF parameters makes decryption fail with an auth error instead
// of producing garbage.
bool encryptToFile(const std::string& password,
                   std::span<const unsigned char> plaintext,
                   const std::string& path,
                   std::string& error);

// Decrypt a vault file into `plaintext`. Returns false on a wrong password,
// a corrupted or truncated file, or any authentication failure.
bool decryptFromFile(const std::string& password,
                     const std::string& path,
                     Bytes& plaintext,
                     std::string& error);

}  // namespace cvalt
