//
// Created by nwagbi on 04/10/2026.
// making my flashdrive an encrypted passkey using libsodium instead of OpenSSL
//
#include "kdf.hpp"

#include <sodium.h>

namespace cvalt {

bool deriveKey(const std::string &password, const unsigned char *salt,
               std::size_t saltLen, unsigned long long opslimit,
               std::size_t memlimit, unsigned char *key, std::string &error) {
  if (sodium_init() < 0) {
    error = "libsodium failed to initialise";
    return false;
  }

  if (saltLen != crypto_pwhash_SALTBYTES) {
    error = "salt must be crypto_pwhash_SALTBYTES bytes";
    return false;
  }

  if (password.empty()) {
    error = "empty password refused";
    return false;
  }

  if (crypto_pwhash(key, KeyBytes, password.c_str(), password.size(), salt,
                    opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) {
    error = "Argon2id failed (out of memory?)";
    return false;
  }

  return true;
}

} // namespace cvalt
