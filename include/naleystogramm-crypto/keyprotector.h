#pragma once
#include "naleystogramm-crypto/bytes.h"
#include <filesystem>

// ── KeyProtector — менеджер мастер-ключа ─────────────────────────────────────
//
// Хранит 32-байтный мастер-ключ в <dataDir>/master.key (права 0600).
// Используется для шифрования E2E-ключей на диске и деривации ключа SQLCipher.
//
// Формат зашифрованных данных: [12 байт nonce][16 байт GCM-tag][N байт ciphertext]

class KeyProtector {
public:
    static KeyProtector& instance();

    // Загрузить или сгенерировать мастер-ключ. Вызывать до всех остальных методов.
    bool init(const std::filesystem::path& dataDir);

    [[nodiscard]] bool isReady() const noexcept { return !m_masterKey.empty(); }

    // HKDF-SHA256(masterKey, label) → дочерний ключ длиной bytes
    [[nodiscard]] Bytes deriveKey(const Bytes& label, int bytes = 32) const;

    // AES-256-GCM шифрование / расшифровка
    [[nodiscard]] Bytes encrypt(const Bytes& plaintext) const;
    [[nodiscard]] Bytes decrypt(const Bytes& blob) const;

private:
    KeyProtector()  = default;
    ~KeyProtector() = default;

    Bytes m_masterKey; // 32 случайных байта
};
