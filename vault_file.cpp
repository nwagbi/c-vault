#include "vault_file.hpp"

#include "kdf.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>

namespace cvalt {
namespace {

constexpr std::array<unsigned char, 4> kMagic{'C', 'V', 'L', 'T'};
constexpr unsigned char kVersion = 1;
constexpr unsigned char kKdfArgon2id13 = 1;

constexpr std::size_t kSaltLen = crypto_pwhash_SALTBYTES;
constexpr std::size_t kNonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr std::size_t kTagLen = crypto_aead_xchacha20poly1305_ietf_ABYTES;

constexpr std::size_t kOffVersion = 4;
constexpr std::size_t kOffKdf = 5;
constexpr std::size_t kOffOps = 6;
constexpr std::size_t kOffMem = 10;
constexpr std::size_t kOffSalt = 14;
constexpr std::size_t kOffNonce = kOffSalt + kSaltLen;
constexpr std::size_t kHeaderLen = kOffNonce + kNonceLen;

// Persisted KDF parameters are untrusted input on read, so clamp them.
constexpr std::uint32_t kMinOps = 1;
constexpr std::uint32_t kMaxOps = 16;
constexpr std::uint32_t kMinMem = 8u * 1024u;
constexpr std::uint32_t kMaxMem = 1024u * 1024u * 1024u;

// Parameters we write for new vaults.
constexpr std::uint32_t kWriteOps = 3;
constexpr std::uint32_t kWriteMem = 64u * 1024u * 1024u;

void putU32(unsigned char* p, std::uint32_t v) {
    p[0] = static_cast<unsigned char>(v & 0xFF);
    p[1] = static_cast<unsigned char>((v >> 8) & 0xFF);
    p[2] = static_cast<unsigned char>((v >> 16) & 0xFF);
    p[3] = static_cast<unsigned char>((v >> 24) & 0xFF);
}

std::uint32_t getU32(const unsigned char* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

bool readAll(const std::string& path, Bytes& out, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open " + path;
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (in.bad()) {
        error = "read failed: " + path;
        return false;
    }
    return true;
}

bool writeAll(const std::string& path, std::span<const unsigned char> data,
              std::string& error) {
    const std::string tmp = path + ".tmp";

    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            error = "cannot create " + tmp;
            return false;
        }
        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
        }
        out.flush();
        if (!out) {
            error = "write failed: " + tmp;
            return false;
        }
    }

    std::error_code ec;
    std::filesystem::remove(path, ec);  // rename does not replace on Windows
    ec.clear();
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        error = "cannot replace " + path + ": " + ec.message();
        return false;
    }
    return true;
}

}  // namespace

bool encryptToFile(const std::string& password,
                   std::span<const unsigned char> plaintext,
                   const std::string& path,
                   std::string& error) {
    if (sodium_init() < 0) {
        error = "libsodium failed to initialise";
        return false;
    }

    std::array<unsigned char, kHeaderLen> header{};
    std::copy(kMagic.begin(), kMagic.end(), header.begin());
    header[kOffVersion] = kVersion;
    header[kOffKdf] = kKdfArgon2id13;
    putU32(header.data() + kOffOps, kWriteOps);
    putU32(header.data() + kOffMem, kWriteMem);
    randombytes_buf(header.data() + kOffSalt, kSaltLen);
    randombytes_buf(header.data() + kOffNonce, kNonceLen);

    std::array<unsigned char, KeyBytes> key{};
    if (!deriveKey(password, header.data() + kOffSalt, kSaltLen,
                   kWriteOps, kWriteMem, key.data(), error)) {
        return false;
    }

    Bytes out(kHeaderLen + plaintext.size() + kTagLen);
    std::copy(header.begin(), header.end(), out.begin());

    unsigned long long cipherLen = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.data() + kHeaderLen, &cipherLen,
        plaintext.data(), plaintext.size(),
        header.data(), header.size(),
        nullptr,
        header.data() + kOffNonce,
        key.data());

    sodium_memzero(key.data(), key.size());

    if (rc != 0) {
        error = "encryption failed";
        return false;
    }

    out.resize(kHeaderLen + static_cast<std::size_t>(cipherLen));
    return writeAll(path, out, error);
}

bool decryptFromFile(const std::string& password,
                     const std::string& path,
                     Bytes& plaintext,
                     std::string& error) {
    if (sodium_init() < 0) {
        error = "libsodium failed to initialise";
        return false;
    }

    Bytes raw;
    if (!readAll(path, raw, error)) {
        return false;
    }

    if (raw.size() < kHeaderLen + kTagLen) {
        error = "not a vault file (too short)";
        return false;
    }

    if (!std::equal(kMagic.begin(), kMagic.end(), raw.begin())) {
        error = "not a vault file (bad magic)";
        return false;
    }

    if (raw[kOffVersion] != kVersion) {
        error = "unsupported vault version " + std::to_string(raw[kOffVersion]);
        return false;
    }

    if (raw[kOffKdf] != kKdfArgon2id13) {
        error = "unsupported KDF id";
        return false;
    }

    const std::uint32_t ops = getU32(raw.data() + kOffOps);
    const std::uint32_t mem = getU32(raw.data() + kOffMem);
    if (ops < kMinOps || ops > kMaxOps || mem < kMinMem || mem > kMaxMem) {
        error = "refusing unsafe KDF parameters in header";
        return false;
    }

    std::array<unsigned char, KeyBytes> key{};
    if (!deriveKey(password, raw.data() + kOffSalt, kSaltLen,
                   ops, mem, key.data(), error)) {
        return false;
    }

    const std::size_t cipherLen = raw.size() - kHeaderLen;
    Bytes out(cipherLen - kTagLen);

    unsigned long long plainLen = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        out.data(), &plainLen,
        nullptr,
        raw.data() + kHeaderLen, cipherLen,
        raw.data(), kHeaderLen,
        raw.data() + kOffNonce,
        key.data());

    sodium_memzero(key.data(), key.size());

    if (rc != 0) {
        error = "wrong password, or the vault file is corrupted";
        return false;
    }

    out.resize(static_cast<std::size_t>(plainLen));
    plaintext = std::move(out);
    return true;
}

}  // namespace cvalt
