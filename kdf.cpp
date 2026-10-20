//
// Created by nwagbi on 04/10/2026.
// making my flashdrive an encrypted passkey using libsodium instead of OpenSSL
//
#include <sodium.h>

#include <array>
#include <cstddef>
#include <iostream>
#include <string>

using namespace std;

constexpr size_t KEY_LEN = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;

string toHex(const unsigned char* data, size_t len) {
    string out(len * 2 + 1, '\0');
    sodium_bin2hex(out.data(), out.size(), data, len);
    out.resize(len * 2);
    return out;
}

bool deriveKey(const string& password,
               const unsigned char* salt,
               unsigned char* key) {
    return crypto_pwhash(
               key, KEY_LEN,
               password.c_str(), password.size(),
               salt,
               crypto_pwhash_OPSLIMIT_INTERACTIVE,
               crypto_pwhash_MEMLIMIT_INTERACTIVE,
               crypto_pwhash_ALG_ARGON2ID13) == 0;
}

int main() {
    if (sodium_init() < 0) {
        cerr << "libsodium failed to initialise\n";
        return 1;
    }

    string password;
    cout << "Password: ";
    getline(cin, password);

    if (password.empty()) {
        cerr << "empty password refused\n";
        return 1;
    }

    array<unsigned char, crypto_pwhash_SALTBYTES> salt{};
    array<unsigned char, KEY_LEN> key1{};
    array<unsigned char, KEY_LEN> key2{};

    randombytes_buf(salt.data(), salt.size());

    if (!deriveKey(password, salt.data(), key1.data()) ||
        !deriveKey(password, salt.data(), key2.data())) {
        cerr << "Argon2id failed (out of memory?)\n";
        return 1;
    }

    if (sodium_memcmp(key1.data(), key2.data(), key1.size()) != 0) {
        cerr << "KDF is not deterministic\n";
        return 1;
    }

    // Demo only: never print a real derived key in production.
    cout << "salt: " << toHex(salt.data(), salt.size()) << '\n';
    cout << "key : " << toHex(key1.data(), key1.size()) << '\n';
    cout << "KDF OK\n";

    sodium_memzero(key1.data(), key1.size());
    sodium_memzero(key2.data(), key2.size());
    sodium_memzero(password.data(), password.size());
    return 0;
}
