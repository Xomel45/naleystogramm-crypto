#pragma once
#include "naleystogramm-crypto/x3dh.h"
#include "naleystogramm-crypto/ratchet.h"
#include <nlohmann/json.hpp>
#include <functional>
#include <map>
#include <unordered_map>
#include <mutex>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>

// One E2E session per peer.
// Handles key generation, bundle exchange, and message encryption.
// Qt-free: uses std types and nlohmann/json instead of QObject/QJsonObject.
class E2EManager {
public:
    E2EManager() = default;
    ~E2EManager();

    // Load or generate our key bundle from disk.
    // ourUuid — без фигурных скобок (строка UUID)
    void init(const std::string& ourUuid, const std::filesystem::path& dataDir);

    // Вызывается при установке сессии с пиром. Аргумент: peerUuid без фигурных скобок.
    std::function<void(const std::string&)> onSessionEstablished;

    // Долгосрочный X3DH identity-ключ (X25519, 32 байта) в base64 — для
    // регистрации на discovery-сервере (поле "pubkey" в POST /register).
    [[nodiscard]] std::string identityPublicKeyBase64() const;

    [[nodiscard]] nlohmann::json ourBundleJson() const;
    [[nodiscard]] nlohmann::json acceptSession(const std::string& peerUuid,
                                                const nlohmann::json& initMsg);
    [[nodiscard]] nlohmann::json initiateSession(const std::string& peerUuid,
                                                  const nlohmann::json& theirBundle);
    void processInitMessage(const std::string& peerUuid, const nlohmann::json& initMsg);

    [[nodiscard]] nlohmann::json                          encrypt(const std::string& peerUuid,
                                                                   const Bytes& plaintext);
    [[nodiscard]] std::expected<Bytes, std::string>       decrypt(const std::string& peerUuid,
                                                                   const nlohmann::json& envelope);
    [[nodiscard]] bool        hasSession(const std::string& peerUuid) const;
    [[nodiscard]] Bytes       snapshotMediaKey(const std::string& peerUuid,
                                               const std::string& callId,
                                               const Bytes& salt);
    [[nodiscard]] std::string getSafetyNumber(const std::string& peerUuid) const;

private:
    Bytes m_ikPriv, m_ikPub, m_ikEdPub;
    Bytes m_spkPriv, m_spkPub, m_spkSig;

    std::vector<std::pair<Bytes, Bytes>> m_otpks; // (priv, pub)

    std::map<std::string, RatchetState>        m_sessions;
    std::map<std::string, Bytes>               m_peerIdentityKeys;   // peer ik (X25519)
    std::map<std::string, Bytes>               m_peerIdentityEdKeys; // peer ik_ed (Ed25519)
    std::unordered_map<std::string,
                       std::unique_ptr<std::mutex>> m_sessionMutexes;
    std::mutex m_mapMutex;

    std::filesystem::path m_keysPath;

    std::mutex* mutexFor(const std::string& uuid);
    void loadOrGenerateKeys();
    void saveKeys();
    Bytes consumeOtpkPriv(const Bytes& pub);
};
