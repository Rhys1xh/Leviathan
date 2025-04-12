//No License at all ... All made for fun ... Do whatever u want with this code fr fr but maybe thank me on discord if ur having fun with it too! Lowkey took me some time to finish cuz i find OpenSSL to be more drippy and sigma than libsodium (which is for the weak obviously ... AND IM NOT WEAK!)

#include <iostream>
#include <fstream>
#include <openssl/ssl.h>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <termios.h>
#include <unistd.h>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/syscall.h>  // For the NR syscall 

// If kernel doesn't support __NR_getrandom (yikes)
#ifndef __NR_getrandom
#define __NR_getrandom 318
#endif

namespace leviathan {

namespace fs = std::filesystem;
using byte = unsigned char;

// =================================================================
//  EXCEPTION HIERARCHY 
// =================================================================
class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& msg) : std::runtime_error(msg) {}
};

class FileException : public std::runtime_error {
public:
    explicit FileException(const std::string& msg) : std::runtime_error(msg) {}
};

class IntegrityException : public CryptoException {
public:
    explicit IntegrityException(const std::string& msg) : CryptoException(msg) {}
};

// =================================================================
//  RAII WRAPPER FOR OPENSSL CONTEXTS 
// =================================================================
template <auto Deleter>
struct OpenSSLDeleter {
    template <typename T>
    void operator()(T* ptr) const noexcept {
        if (ptr) Deleter(ptr);
    }
};

using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, OpenSSLDeleter<EVP_CIPHER_CTX_free>>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, OpenSSLDeleter<EVP_MD_CTX_free>>;

// =================================================================
//  SECURE MEMORY ALLOCATOR 
// =================================================================
template <typename T>
class SecureAllocator : public std::allocator<T> {
public:
    template <class U> struct rebind { using other = SecureAllocator<U>; };

    T* allocate(size_t n) {
        size_t total_size = n * sizeof(T);
        void* ptr = secure_mmap(total_size);
        if (ptr == MAP_FAILED) throw std::bad_alloc();
        return static_cast<T*>(ptr);
    }

    void deallocate(T* p, size_t n) {
        if (p) {
            OPENSSL_cleanse(p, n * sizeof(T));
            secure_munmap(p, n * sizeof(T));
        }
    }

private:
    static void* secure_mmap(size_t size) {
        void* ptr = mmap(nullptr, size + 4096, PROT_READ | PROT_WRITE, 
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) return MAP_FAILED;

        if (mlock(ptr, size) != 0) {
            munmap(ptr, size + 4096);
            return MAP_FAILED;
        }

        mprotect(static_cast<byte*>(ptr) + size, 4096, PROT_NONE);
        return ptr;
    }

    static void secure_munmap(void* ptr, size_t size) {
        munlock(ptr, size);
        munmap(ptr, size + 4096);
    }
};

using secure_string = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
using secure_vector = std::vector<byte, SecureAllocator<byte>>;

// =================================================================
// OPENSSL INITIALIZATION 
// =================================================================
class OpenSSLInitializer {
public:
    OpenSSLInitializer() {
        std::call_once(init_flag_, []() {
            OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                              OPENSSL_INIT_ADD_ALL_CIPHERS |
                              OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
            #if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
            OPENSSL_init_ssl(0, nullptr);
            #endif
            EVP_add_cipher(EVP_aes_256_cbc());
            EVP_add_digest(EVP_sha512());
        });
    }

private:
    static std::once_flag init_flag_;
};

std::once_flag OpenSSLInitializer::init_flag_;

// =================================================================
// SYSTEM HARDENING 
// =================================================================
class SystemHardener {
public:
    SystemHardener() {
        // Disable core dumps
        prctl(PR_SET_DUMPABLE, 0);
        
        // Ignore fatal signals
        signal(SIGSEGV, SIG_DFL);
        signal(SIGABRT, SIG_DFL);
        
        // Verify kernel RNG is available
        byte test;
        if (syscall(__NR_getrandom, &test, 1, GRND_RANDOM) != 1) {
            throw std::runtime_error("Kernel RNG not available");
        }
    }
};

// =================================================================
//  CRYPTO UTILITIES 
// =================================================================
class CryptoUtil {
public:
    static constexpr size_t AES_KEY_SIZE = 32;
    static constexpr size_t AES_BLOCK_SIZE = 16;
    static constexpr size_t SALT_SIZE = 16;
    static constexpr size_t IV_SIZE = 16;
    static constexpr size_t HMAC_SIZE = SHA512_DIGEST_LENGTH;
    static constexpr int PBKDF2_ITERATIONS = 210000;

    static void generateRandom(byte* buf, size_t len) {
        std::lock_guard<std::mutex> lock(rand_mutex_);
        if (syscall(__NR_getrandom, buf, len, GRND_RANDOM) != static_cast<ssize_t>(len)) {
            throw CryptoException("Secure random generation failed");
        }
    }

    static void deriveKey(const secure_string& password, const byte* salt, byte* key) {
        if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), 
                             salt, SALT_SIZE,
                             PBKDF2_ITERATIONS, EVP_sha256(), 
                             AES_KEY_SIZE, key) != 1) {
            throw CryptoException("Key derivation failed");
        }
    }

    static void computeHMAC(const byte* key, size_t key_len, 
                          const byte* data, size_t data_len,
                          byte* hmac) {
        unsigned int hmac_len;
        if (::HMAC(EVP_sha512(), key, key_len, data, data_len, hmac, &hmac_len) == nullptr) {
            throw CryptoException("HMAC computation failed");
        }
    }

    static void encrypt(const std::string& plaintext, 
                       const secure_string& password,
                       secure_vector& ciphertext) {
        OpenSSLInitializer init;
        
        byte salt[SALT_SIZE], iv[IV_SIZE], key[AES_KEY_SIZE], hmac_key[AES_KEY_SIZE];
        generateRandom(salt, SALT_SIZE);
        generateRandom(iv, IV_SIZE);
        
        deriveKey(password, salt, key);
        
        secure_string hmac_password = password;
        hmac_password.append(std::to_string(PBKDF2_ITERATIONS));
        deriveKey(hmac_password, salt, hmac_key);

        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) throw CryptoException("Failed to create cipher context");

        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            throw CryptoException("Encryption initialization failed");
        }

        ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE + HMAC_SIZE);
        int len, ciphertext_len = 0;

        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                            reinterpret_cast<const byte*>(plaintext.c_str()), 
                            plaintext.size()) != 1) {
            throw CryptoException("Encryption failed");
        }
        ciphertext_len += len;

        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + ciphertext_len, &len) != 1) {
            throw CryptoException("Encryption finalization failed");
        }
        ciphertext_len += len;

        byte hmac[HMAC_SIZE];
        secure_vector hmac_data;
        hmac_data.reserve(SALT_SIZE + IV_SIZE + ciphertext_len);
        hmac_data.insert(hmac_data.end(), salt, salt + SALT_SIZE);
        hmac_data.insert(hmac_data.end(), iv, iv + IV_SIZE);
        hmac_data.insert(hmac_data.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

        computeHMAC(hmac_key, sizeof(hmac_key), 
                   hmac_data.data(), hmac_data.size(), 
                   hmac);

        std::copy(hmac, hmac + HMAC_SIZE, ciphertext.begin() + ciphertext_len);
        ciphertext.resize(ciphertext_len + HMAC_SIZE);

        ciphertext.insert(ciphertext.begin(), iv, iv + IV_SIZE);
        ciphertext.insert(ciphertext.begin(), salt, salt + SALT_SIZE);
    }

    static std::string decrypt(const secure_vector& ciphertext,
                              const secure_string& password) {
        if (ciphertext.size() < SALT_SIZE + IV_SIZE + HMAC_SIZE) {
            throw IntegrityException("Invalid ciphertext size");
        }

        OpenSSLInitializer init;

        const byte* salt = ciphertext.data();
        const byte* iv = salt + SALT_SIZE;
        const byte* encrypted_data = iv + IV_SIZE;
        size_t encrypted_len = ciphertext.size() - SALT_SIZE - IV_SIZE - HMAC_SIZE;
        const byte* received_hmac = encrypted_data + encrypted_len;

        byte key[AES_KEY_SIZE], hmac_key[AES_KEY_SIZE];
        deriveKey(password, salt, key);
        
        secure_string hmac_password = password;
        hmac_password.append(std::to_string(PBKDF2_ITERATIONS));
        deriveKey(hmac_password, salt, hmac_key);

        byte computed_hmac[HMAC_SIZE];
        computeHMAC(hmac_key, sizeof(hmac_key), 
                   ciphertext.data(), 
                   SALT_SIZE + IV_SIZE + encrypted_len,
                   computed_hmac);

        if (CRYPTO_memcmp(received_hmac, computed_hmac, HMAC_SIZE) != 0) {
            throw IntegrityException("HMAC verification failed - data tampered");
        }

        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) throw CryptoException("Failed to create cipher context");

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            throw CryptoException("Decryption initialization failed");
        }

        std::string plaintext(encrypted_len + AES_BLOCK_SIZE, '\0');
        int len, plaintext_len = 0;

        if (EVP_DecryptUpdate(ctx.get(), reinterpret_cast<byte*>(&plaintext[0]), &len,
                             encrypted_data, encrypted_len) != 1) {
            throw CryptoException("Decryption failed");
        }
        plaintext_len += len;

        if (EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<byte*>(&plaintext[0] + plaintext_len), &len) != 1) {
            throw IntegrityException("Decryption finalization failed - possible corruption");
        }
        plaintext_len += len;

        plaintext.resize(plaintext_len);
        return plaintext;
    }

private:
    static std::mutex rand_mutex_;
};

std::mutex CryptoUtil::rand_mutex_;

// =================================================================
//  FILE HANDLER 
// =================================================================
class FileHandler {
public:
    static void writeFile(const fs::path& path, 
                         const secure_vector& data) {
        std::ofstream file(path, std::ios::binary);
        if (!file) {
            throw FileException("Failed to open file for writing: " + path.string());
        }
        
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        if (!file) {
            throw FileException("Failed to write to file: " + path.string());
        }
    }

    static secure_vector readFile(const fs::path& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            throw FileException("Failed to open file: " + path.string());
        }

        auto size = file.tellg();
        if (size <= 0) {
            throw FileException("Empty or invalid file: " + path.string());
        }

        file.seekg(0);
        secure_vector data(size);
        
        if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
            throw FileException("Failed to read file: " + path.string());
        }

        return data;
    }

    static bool fileExists(const fs::path& path) {
        return fs::exists(path);
    }
};

// =================================================================
//  MAIN APPLICATION 
// =================================================================
class LeviathanApp {
public:
    void run() {
        SystemHardener hardener;
        OpenSSLInitializer init;
        
        while (true) {
            try {
                displayMenu();
                int choice = getMenuChoice();
                
                switch (choice) {
                    case 1: encryptFlow(); break;
                    case 2: decryptFlow(); break;
                    case 3: modifyFlow(); break;
                    case 0: return;
                    default: std::cout << "Invalid choice.\n";
                }
            } catch (const IntegrityException& e) {
                std::cerr << "\nSECURITY ALERT: " << e.what() << "\n";
                std::cerr << "The file may have been tampered with or corrupted.\n\n";
            } catch (const CryptoException& e) {
                std::cerr << "\nCRYPTO ERROR: " << e.what() << "\n\n";
            } catch (const FileException& e) {
                std::cerr << "\nFILE ERROR: " << e.what() << "\n\n";
            } catch (const std::exception& e) {
                std::cerr << "\nERROR: " << e.what() << "\n\n";
            }
            
            pause();
        }
    }

private:
    void clearScreen() const {
        std::cout << "\033[2J\033[H";
    }

    void pause() const {
        std::cout << "Press Enter to continue...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    int getMenuChoice() const {
        int choice;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return choice;
    }

    void displayMenu() const {
        clearScreen();
        std::cout << "\n[ Leviathan - Secure Data Vault - By Rhys1xh (Timucin Danaci) ]\n"
                     "----------------------------------\n"
                     "1. Encrypt Text to .lvt File\n"
                     "2. Decrypt and View .lvt File\n"
                     "3. Modify .lvt File\n"
                     "0. Exit\n"
                     "Select option: ";
    }

    void encryptFlow() {
        clearScreen();
        std::cout << "Enter text to encrypt (end with blank line):\n";
        
        std::string content;
        for (std::string line; std::getline(std::cin, line) && !line.empty(); ) {
            content += line + '\n';
        }
        
        if (content.empty()) {
            throw std::runtime_error("No content provided");
        }

        auto password = getSecureInput("Enter password:");
        auto confirm = getSecureInput("Confirm password:");
        
        if (password != confirm) {
            throw std::runtime_error("Passwords do not match");
        }

        auto filename = getInput("Enter output filename (.lvt):");
        if (!endsWith(filename, ".lvt")) {
            filename += ".lvt";
        }

        fs::path filepath(filename);
        if (FileHandler::fileExists(filepath)) {
            auto overwrite = getInput("File exists. Overwrite? (y/N): ");
            if (overwrite.empty() || tolower(overwrite[0]) != 'y') {
                return;
            }
        }

        secure_vector ciphertext;
        CryptoUtil::encrypt(content, password, ciphertext);
        FileHandler::writeFile(filepath, ciphertext);

        clearScreen();
        std::cout << "File encrypted successfully to " << filepath << "\n";
    }

    void decryptFlow() {
        clearScreen();
        auto filename = getInput("Enter .lvt filename:");
        if (!endsWith(filename, ".lvt")) {
            filename += ".lvt";
        }

        auto password = getSecureInput("Enter password:");
        auto ciphertext = FileHandler::readFile(filename);
        auto plaintext = CryptoUtil::decrypt(ciphertext, password);

        clearScreen();
        std::cout << "\nDecrypted content:\n" << plaintext << "\n";
    }

    void modifyFlow() {
        clearScreen();
        auto filename = getInput("Enter .lvt filename:");
        if (!endsWith(filename, ".lvt")) {
            filename += ".lvt";
        }

        auto password = getSecureInput("Enter password:");
        auto ciphertext = FileHandler::readFile(filename);
        auto plaintext = CryptoUtil::decrypt(ciphertext, password);

        std::cout << "\nCurrent content:\n" << plaintext << "\n";
        std::cout << "Enter new content (end with blank line):\n";
        
        std::string newContent;
        for (std::string line; std::getline(std::cin, line) && !line.empty(); ) {
            newContent += line + '\n';
        }

        if (newContent.empty()) {
            throw std::runtime_error("No content provided");
        }

        secure_vector newCiphertext;
        CryptoUtil::encrypt(newContent, password, newCiphertext);
        FileHandler::writeFile(filename, newCiphertext);

        clearScreen();
        std::cout << "File updated successfully.\n";
    }

    secure_string getSecureInput(const std::string& prompt) {
        std::cout << prompt << ' ';
        
        termios oldt;
        tcgetattr(STDIN_FILENO, &oldt);
        termios newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        
        secure_string password;
        std::getline(std::cin, password);
        
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << '\n';
        
        return password;
    }

    std::string getInput(const std::string& prompt) {
        std::cout << prompt << ' ';
        std::string input;
        std::getline(std::cin, input);
        return input;
    }

    bool endsWith(const std::string& str, const std::string& suffix) {
        if (str.length() < suffix.length()) return false;
        return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
    }
};

} // namespace leviathan (For blind people (Me!))

int main() {
    try {
        leviathan::LeviathanApp app;
        app.run();
    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}