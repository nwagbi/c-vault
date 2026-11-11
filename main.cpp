#include "vault_file.hpp"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#ifdef _WIN32
#include <conio.h>
#include <io.h>
#endif

namespace {

using cvalt::Bytes;

constexpr const char* kUsage =
    "usage:\n"
    "  cvalt encrypt <plaintext-file> <vault-file>\n"
    "  cvalt decrypt <vault-file> <plaintext-file>\n"
    "  cvalt selftest\n";

void wipe(std::string& s) {
    if (!s.empty()) {
        sodium_memzero(s.data(), s.size());
    }
    s.clear();
}

bool readBytes(const std::string& path, Bytes& out, std::string& error) {
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

bool writeBytes(const std::string& path, const Bytes& data, std::string& error) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot create " + path;
        return false;
    }
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    out.flush();
    if (!out) {
        error = "write failed: " + path;
        return false;
    }
    return true;
}

bool promptPassword(const std::string& label, std::string& password) {
    std::cout << label << std::flush;

#ifdef _WIN32
    // Piped/redirected stdin cannot use _getch; read a line instead so the CLI
    // stays scriptable (tests, automation).
    if (!_isatty(_fileno(stdin))) {
        if (!std::getline(std::cin, password)) {
            return false;
        }
        return true;
    }

    password.clear();
    for (;;) {
        const int c = _getch();
        if (c == '\r' || c == '\n') {
            std::cout << '\n';
            return true;
        }
        if (c == 3) {  // Ctrl-C
            std::cout << '\n';
            return false;
        }
        if (c == 8 || c == 127) {  // Backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b" << std::flush;
            }
            continue;
        }
        if (c == 0 || c == 224) {
            _getch();  // swallow arrow/function-key second byte
            continue;
        }
        password.push_back(static_cast<char>(c));
        std::cout << '*' << std::flush;
    }
#else
    if (!std::getline(std::cin, password)) {
        return false;
    }
    return true;
#endif
}

int cmdEncrypt(const char* plainPath, const char* vaultPath) {
    Bytes plain;
    std::string error;
    if (!readBytes(plainPath, plain, error)) {
        std::cerr << "cvalt: " << error << '\n';
        return 1;
    }

    std::string password;
    std::string confirm;
    if (!promptPassword("Password: ", password)) {
        std::cerr << "cvalt: no password\n";
        return 1;
    }
    if (password.empty()) {
        std::cerr << "cvalt: empty password refused\n";
        return 1;
    }
    if (!promptPassword("Confirm : ", confirm)) {
        wipe(password);
        std::cerr << "cvalt: no confirmation\n";
        return 1;
    }
    if (password != confirm) {
        wipe(password);
        wipe(confirm);
        std::cerr << "cvalt: passwords do not match\n";
        return 1;
    }
    wipe(confirm);

    const bool ok = cvalt::encryptToFile(password, plain, vaultPath, error);
    wipe(password);

    if (!ok) {
        std::cerr << "cvalt: " << error << '\n';
        return 1;
    }

    std::cout << "wrote " << vaultPath << " (" << std::filesystem::file_size(vaultPath)
              << " bytes, " << plain.size() << " bytes of plaintext)\n";
    return 0;
}

int cmdDecrypt(const char* vaultPath, const char* plainPath) {
    std::string password;
    if (!promptPassword("Password: ", password)) {
        std::cerr << "cvalt: no password\n";
        return 1;
    }
    if (password.empty()) {
        std::cerr << "cvalt: empty password refused\n";
        return 1;
    }

    Bytes plain;
    std::string error;
    const bool ok = cvalt::decryptFromFile(password, vaultPath, plain, error);
    wipe(password);

    if (!ok) {
        std::cerr << "cvalt: " << error << '\n';
        return 1;
    }

    if (!writeBytes(plainPath, plain, error)) {
        std::cerr << "cvalt: " << error << '\n';
        return 1;
    }

    // Wipe the recovered plaintext before releasing it.
    if (!plain.empty()) {
        sodium_memzero(plain.data(), plain.size());
    }
    std::cout << "wrote " << plainPath << " (" << plain.size() << " bytes)\n";
    return 0;
}

struct TestRun {
    int failures = 0;

    void check(bool cond, const char* name, const std::string& detail = {}) {
        if (cond) {
            std::cout << "PASS  " << name << '\n';
        } else {
            std::cout << "FAIL  " << name;
            if (!detail.empty()) {
                std::cout << "  (" << detail << ')';
            }
            std::cout << '\n';
            ++failures;
        }
    }
};

int cmdSelftest() {
    if (sodium_init() < 0) {
        std::cerr << "cvalt: libsodium failed to initialise\n";
        return 1;
    }

    TestRun t;
    const std::filesystem::path dir = std::filesystem::temp_directory_path();
    const std::string vault = (dir / "cvalt-selftest.cvlt").string();
    const std::string other = (dir / "cvalt-selftest-2.cvlt").string();

    const std::string password = "correct horse battery staple";
    const std::string payload = std::string("hello\0vault\n", 12) + "line two\n";

    Bytes plain(payload.begin(), payload.end());
    std::string error;

    t.check(cvalt::encryptToFile(password, plain, vault, error), "encrypt", error);

    Bytes recovered;
    t.check(cvalt::decryptFromFile(password, vault, recovered, error), "decrypt", error);
    t.check(recovered == plain, "round-trip is byte-exact");

    Bytes empty;
    std::string emptyErr;
    t.check(cvalt::encryptToFile(password, empty, other, emptyErr), "encrypt empty payload", emptyErr);
    Bytes emptyOut;
    t.check(cvalt::decryptFromFile(password, other, emptyOut, emptyErr) && emptyOut.empty(),
            "empty payload round-trip", emptyErr);

    Bytes wrongOut;
    t.check(!cvalt::decryptFromFile("wrong password", vault, wrongOut, error),
            "wrong password rejected");

    // Same plaintext + password must still produce different files (fresh salt/nonce).
    Bytes same;
    std::string sameErr;
    t.check(cvalt::encryptToFile(password, plain, other, sameErr), "second encrypt", sameErr);
    Bytes a;
    Bytes b;
    std::string readErr;
    t.check(readBytes(vault, a, readErr) && readBytes(other, b, readErr) && a != b,
            "salt/nonce are fresh per encryption", readErr);

    auto tamper = [&](std::size_t offset, const char* name, const char* note) {
        Bytes raw;
        std::string err;
        if (!readBytes(vault, raw, err)) {
            t.check(false, name, err);
            return;
        }
        if (offset >= raw.size()) {
            t.check(false, name, "offset out of range");
            return;
        }
        raw[offset] ^= 0x01;
        if (!writeBytes(other, raw, err)) {
            t.check(false, name, err);
            return;
        }
        Bytes out;
        t.check(!cvalt::decryptFromFile(password, other, out, err), name, note);
    };

    tamper(a.size() - 1, "flipped ciphertext byte rejected", "");
    tamper(20, "tampered salt rejected", "");          // inside the salt field
    tamper(4, "tampered version rejected", "");
    tamper(0, "tampered magic rejected", "");

    // Truncation
    {
        Bytes raw;
        std::string err;
        if (readBytes(vault, raw, err) && raw.size() > 20) {
            raw.resize(raw.size() - 10);
            Bytes out;
            t.check(writeBytes(other, raw, err) &&
                        !cvalt::decryptFromFile(password, other, out, err),
                    "truncated file rejected", err);
        } else {
            t.check(false, "truncated file rejected", err);
        }
    }

    std::error_code ec;
    std::filesystem::remove(vault, ec);
    std::filesystem::remove(other, ec);

    std::cout << (t.failures == 0 ? "selftest OK\n" : "selftest FAILED\n");
    return t.failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << kUsage;
        return 2;
    }

    const std::string cmd = argv[1];
    if (cmd == "encrypt" && argc == 4) {
        return cmdEncrypt(argv[2], argv[3]);
    }
    if (cmd == "decrypt" && argc == 4) {
        return cmdDecrypt(argv[2], argv[3]);
    }
    if (cmd == "selftest" && argc == 2) {
        return cmdSelftest();
    }

    std::cerr << kUsage;
    return 2;
}
