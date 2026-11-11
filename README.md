# c-vault

Portable encrypted password vault in C++ — libsodium, Argon2id, XChaCha20-Poly1305.

The vault is a single self-contained file: a small header (KDF parameters, salt,
nonce) followed by the ciphertext and its Poly1305 tag. No OpenSSL, no external
crypto code.

## Layout

```
offset  size  field
0       4     magic "CVLT"
4       1     format version (1)
5       1     KDF id (1 = Argon2id13)
6       4     opslimit  (u32 LE)
10      4     memlimit  (u32 LE, bytes)
14      16    salt  (crypto_pwhash_SALTBYTES)
30      24    nonce (XChaCha20-Poly1305 IETF)
54      n+16  ciphertext + tag
```

The header is passed to the AEAD as associated data, so editing the salt, nonce,
version or KDF parameters fails authentication instead of silently changing how
the key is derived. On read, KDF parameters are clamped (ops 1–16, memory
8 KiB–1 GiB) so a hostile file cannot ask for absurd work.

## Build

Requires MSYS2 UCRT64 (`C:\msys64\ucrt64`, g++ 15 + libsodium).

```powershell
.\build.ps1              # static build -> build\cvalt.exe
.\build\cvalt.exe selftest
```

Or with CMake:

```powershell
cmake -S . -B build-cmake -G "MinGW Makefiles" `
  -DSODIUM_INCLUDE_DIR=C:/msys64/ucrt64/include `
  -DSODIUM_LIBRARY=C:/msys64/ucrt64/lib/libsodium.a
cmake --build build-cmake
```

## Usage

```powershell
.\build\cvalt.exe encrypt secrets.txt vault.cvlt   # prompts twice, no echo
.\build\cvalt.exe decrypt vault.cvlt secrets.txt   # prompts once
.\build\cvalt.exe selftest
```

Password input reads the console without echo; when stdin is piped (tests,
automation) it reads a line instead.

## Selftest

`cvalt selftest` covers: byte-exact round-trip, empty payload, wrong password,
fresh salt/nonce per encryption, single-bit tampering of ciphertext / salt /
version / magic, and truncation.

## Roadmap

- [x] Argon2id13 KDF wrapper with explicit parameters
- [x] XChaCha20-Poly1305 vault container (create / open)
- [ ] Entry model (add / list / show) instead of raw text payloads
- [ ] WASM build of the crypto core
- [ ] Firmware / USB-HID layer
