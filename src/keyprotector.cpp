#include "naleystogramm-crypto/keyprotector.h"
#include "naleystogramm-crypto/openssl_raii.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <fstream>
#include <sys/stat.h>
#include <cstdio>

KeyProtector& KeyProtector::instance() {
    static KeyProtector self;
    return self;
}

bool KeyProtector::init(const std::filesystem::path& dataDir) {
    std::error_code ec;
    std::filesystem::create_directories(dataDir, ec);

    const std::filesystem::path path = dataDir / "master.key";

    if (std::filesystem::exists(path, ec)) {
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            fprintf(stderr, "[KeyProtector] Не удалось открыть master.key\n");
            return false;
        }
        m_masterKey.assign(std::istreambuf_iterator<char>(f), {});
        if (m_masterKey.size() != 32) {
            fprintf(stderr, "[KeyProtector] master.key повреждён (размер %zu ≠ 32)\n",
                    m_masterKey.size());
            m_masterKey.clear();
            return false;
        }
        return true;
    }

    // Первый запуск — генерируем 32 случайных байта
    m_masterKey.resize(32);
    if (RAND_bytes(m_masterKey.data(), 32) != 1) {
        fprintf(stderr, "[KeyProtector] RAND_bytes провалился\n");
        m_masterKey.clear();
        return false;
    }

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        fprintf(stderr, "[KeyProtector] Не удалось создать master.key\n");
        m_masterKey.clear();
        return false;
    }
    f.write(reinterpret_cast<const char*>(m_masterKey.data()), 32);
    f.close();

#ifndef _WIN32
    ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
#endif
    return true;
}

Bytes KeyProtector::deriveKey(const Bytes& label, int bytes) const {
    if (m_masterKey.empty()) {
        fprintf(stderr, "[KeyProtector] deriveKey вызван до init()\n");
        return {};
    }

    static const Bytes kSalt(32, 0);

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx) return {};

    Bytes out(static_cast<size_t>(bytes), 0);
    size_t outLen = static_cast<size_t>(bytes);

    if (EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), kSalt.data(),
            static_cast<int>(kSalt.size())) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), m_masterKey.data(),
            static_cast<int>(m_masterKey.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), label.data(),
            static_cast<int>(label.size())) <= 0 ||
        EVP_PKEY_derive(ctx.get(), out.data(), &outLen) <= 0)
    {
        fprintf(stderr, "[KeyProtector] HKDF деривация провалилась\n");
        return {};
    }
    return out;
}

Bytes KeyProtector::encrypt(const Bytes& plaintext) const {
    if (!isReady()) return {};

    const Bytes encKey = deriveKey(sv2bytes("naleystogramm-file-enc-v1"));
    if (encKey.empty()) return {};

    Bytes nonce(12, 0);
    if (RAND_bytes(nonce.data(), 12) != 1) {
        fprintf(stderr, "[KeyProtector] RAND_bytes для nonce провалился\n");
        return {};
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return {};

    Bytes ciphertext(plaintext.size(), 0);
    Bytes tag(16, 0);
    int len = 0;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
            encKey.data(), nonce.data()) != 1)
    {
        fprintf(stderr, "[KeyProtector] Инициализация шифрования провалилась\n");
        return {};
    }

    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
            plaintext.data(), static_cast<int>(plaintext.size())) != 1)
    {
        fprintf(stderr, "[KeyProtector] EVP_EncryptUpdate провалился\n");
        return {};
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &finalLen) != 1) {
        fprintf(stderr, "[KeyProtector] EVP_EncryptFinal_ex провалился\n");
        return {};
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        fprintf(stderr, "[KeyProtector] Получение GCM-тега провалилось\n");
        return {};
    }

    return nonce + tag + ciphertext;
}

Bytes KeyProtector::decrypt(const Bytes& blob) const {
    if (!isReady()) return {};
    if (blob.size() < 28) {
        fprintf(stderr, "[KeyProtector] decrypt: блоб слишком мал (%zu байт)\n", blob.size());
        return {};
    }

    const Bytes encKey = deriveKey(sv2bytes("naleystogramm-file-enc-v1"));
    if (encKey.empty()) return {};

    const Bytes nonce      = bytesLeft(blob, 12);
    const Bytes tag        = bytesMid(blob, 12, 16);
    const Bytes ciphertext = bytesMid(blob, 28);

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return {};

    Bytes plaintext(ciphertext.size(), 0);
    int len = 0;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
            encKey.data(), nonce.data()) != 1)
    {
        fprintf(stderr, "[KeyProtector] Инициализация расшифровки провалилась\n");
        return {};
    }

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
            ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
    {
        fprintf(stderr, "[KeyProtector] EVP_DecryptUpdate провалился\n");
        return {};
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
            const_cast<uint8_t*>(tag.data())) != 1)
    {
        fprintf(stderr, "[KeyProtector] Установка GCM-тега провалилась\n");
        return {};
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &finalLen) <= 0) {
        fprintf(stderr, "[KeyProtector] GCM-тег не совпал — данные повреждены или неверный ключ\n");
        return {};
    }

    return plaintext;
}
