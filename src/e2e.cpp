#include "naleystogramm-crypto/e2e.h"
#include "naleystogramm-crypto/securedata.h"
#include "naleystogramm-crypto/keyprotector.h"
#include "naleystogramm-crypto/x3dh.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <fstream>
#include <algorithm>
#include <cstdio>
#ifndef _WIN32
#include <sys/stat.h>
#endif

static constexpr int kOtpkPoolSize = 100;

E2EManager::~E2EManager() {
    m_sessionMutexes.clear();
    secureZero(m_ikPriv);
    secureZero(m_spkPriv);
    for (auto& kp : m_otpks) secureZero(kp.first);
    m_otpks.clear();
}

void E2EManager::init(const std::string& ourUuid, const std::filesystem::path& dataDir) {
    const std::filesystem::path keysDir = dataDir / "keys";
    std::error_code ec;
    std::filesystem::create_directories(keysDir, ec);
    m_keysPath = keysDir / (ourUuid + ".json");
    loadOrGenerateKeys();
}

// ── Key persistence ───────────────────────────────────────────────────────

void E2EManager::loadOrGenerateKeys() {
    if (std::filesystem::exists(m_keysPath)) {
        std::ifstream f(m_keysPath, std::ios::binary);
        if (!f) {
            fprintf(stderr, "[E2E] Не удалось открыть %s\n", m_keysPath.c_str());
            return;
        }
        Bytes raw(std::istreambuf_iterator<char>(f), {});

        if (!KeyProtector::instance().isReady()) {
            fprintf(stderr, "[E2E] KeyProtector не готов — отказываемся загружать ключи\n");
            return;
        }

        const bool looksLikeJson = !raw.empty() && raw[0] == static_cast<uint8_t>('{');

        Bytes jsonBytes;
        if (looksLikeJson) {
            fprintf(stderr, "[E2E] keys.json в открытом виде — выполняем миграцию\n");
            jsonBytes = raw;
        } else {
            jsonBytes = KeyProtector::instance().decrypt(raw);
            if (jsonBytes.empty()) {
                fprintf(stderr, "[E2E] Не удалось расшифровать keys.json\n");
                return;
            }
        }

        nlohmann::json obj;
        try {
            obj = nlohmann::json::parse(jsonBytes.begin(), jsonBytes.end());
        } catch (...) {
            fprintf(stderr, "[E2E] Невалидный JSON в keys.json\n");
            return;
        }

        m_ikPriv  = bytesFromHex(obj.value("ik_priv",  std::string{}));
        m_ikPub   = bytesFromHex(obj.value("ik_pub",   std::string{}));
        m_spkPriv = bytesFromHex(obj.value("spk_priv", std::string{}));
        m_spkPub  = bytesFromHex(obj.value("spk_pub",  std::string{}));
        m_spkSig  = bytesFromHex(obj.value("spk_sig",  std::string{}));

        m_otpks.clear();
        if (obj.contains("otpks") && obj["otpks"].is_array()) {
            for (const auto& v : obj["otpks"]) {
                m_otpks.push_back({
                    bytesFromHex(v.value("priv", std::string{})),
                    bytesFromHex(v.value("pub",  std::string{}))
                });
            }
        }

        if (!m_ikPriv.empty() && !m_spkPriv.empty()) {
            m_ikEdPub = X3DH::ikPrivToEdPub(m_ikPriv);
            if (looksLikeJson) {
                saveKeys();
                fprintf(stderr, "[E2E] Миграция keys.json завершена\n");
            }
            return;
        }
    }

    // Generate fresh bundle
    Bytes dummyPriv, dummyPub;
    if (!X3DH::generateBundle(m_ikPriv, m_ikPub,
                               m_spkPriv, m_spkPub, m_spkSig,
                               dummyPriv, dummyPub))
    {
        fprintf(stderr, "[E2E] Key generation failed\n");
        return;
    }

    m_otpks.clear();
    for (int i = 0; i < kOtpkPoolSize; ++i) {
        Bytes priv, pub, d1, d2, d3;
        [[maybe_unused]] const bool ok =
            X3DH::generateBundle(d1, d2, d3, d3, d3, priv, pub);
        m_otpks.push_back({priv, pub});
    }

    m_ikEdPub = X3DH::ikPrivToEdPub(m_ikPriv);
    saveKeys();
}

void E2EManager::saveKeys() {
    if (!KeyProtector::instance().isReady()) {
        fprintf(stderr, "[E2E] KeyProtector не готов — keys.json НЕ сохранён\n");
        std::filesystem::remove(m_keysPath);
        return;
    }

    nlohmann::json obj;
    obj["ik_priv"]  = bytesToHex(m_ikPriv);
    obj["ik_pub"]   = bytesToHex(m_ikPub);
    obj["spk_priv"] = bytesToHex(m_spkPriv);
    obj["spk_pub"]  = bytesToHex(m_spkPub);
    obj["spk_sig"]  = bytesToHex(m_spkSig);

    nlohmann::json arr = nlohmann::json::array();
    for (const auto& kp : m_otpks) {
        nlohmann::json o;
        o["priv"] = bytesToHex(kp.first);
        o["pub"]  = bytesToHex(kp.second);
        arr.push_back(o);
    }
    obj["otpks"] = arr;

    const std::string jsonStr = obj.dump();
    const Bytes jsonBytes(jsonStr.begin(), jsonStr.end());
    const Bytes encrypted = KeyProtector::instance().encrypt(jsonBytes);
    if (encrypted.empty()) {
        fprintf(stderr, "[E2E] Шифрование keys.json провалилось\n");
        std::filesystem::remove(m_keysPath);
        return;
    }

    std::ofstream f(m_keysPath, std::ios::binary | std::ios::trunc);
    if (!f) {
        fprintf(stderr, "[E2E] Не удалось открыть keys.json для записи\n");
        return;
    }
    f.write(reinterpret_cast<const char*>(encrypted.data()),
            static_cast<std::streamsize>(encrypted.size()));
    f.close();

#ifndef _WIN32
    // Приватные ключи (даже зашифрованные) — только для владельца.
    ::chmod(m_keysPath.c_str(), S_IRUSR | S_IWUSR);
#endif
}

// ── Bundle serialization ──────────────────────────────────────────────────

std::string E2EManager::identityPublicKeyBase64() const {
    return bytesToBase64(m_ikPub);
}

nlohmann::json E2EManager::ourBundleJson() const {
    nlohmann::json bundle;
    bundle["ik"]      = bytesToHex(m_ikPub);
    bundle["spk"]     = bytesToHex(m_spkPub);
    bundle["spk_sig"] = bytesToHex(m_spkSig);
    if (!m_ikEdPub.empty())
        bundle["ik_ed"] = bytesToHex(m_ikEdPub);
    if (!m_otpks.empty())
        bundle["otpk"] = bytesToHex(m_otpks.front().second);
    return bundle;
}

// ── Session establishment ─────────────────────────────────────────────────

nlohmann::json E2EManager::initiateSession(const std::string& peerUuid,
                                             const nlohmann::json& theirBundle) {
    X3DHKeyBundle b;
    b.identityKey     = bytesFromHex(theirBundle.value("ik",      std::string{}));
    b.signedPreKey    = bytesFromHex(theirBundle.value("spk",     std::string{}));
    b.signedPreKeySig = bytesFromHex(theirBundle.value("spk_sig", std::string{}));
    if (theirBundle.contains("ik_ed"))
        b.ikEdPub = bytesFromHex(theirBundle["ik_ed"].get<std::string>());
    if (theirBundle.contains("otpk"))
        b.oneTimePreKey = bytesFromHex(theirBundle["otpk"].get<std::string>());

    Bytes ephPub;
    auto secret = X3DH::initiatorAgreement(m_ikPriv, m_ikPub, b, ephPub);
    if (!secret) {
        fprintf(stderr, "[E2E] initiatorAgreement failed\n");
        return nullptr;
    }

    m_peerIdentityKeys[peerUuid]   = b.identityKey;
    m_peerIdentityEdKeys[peerUuid] = b.ikEdPub;   // для привязки в числе безопасности
    m_sessions[peerUuid] = DoubleRatchet::initSender(*secret, b.signedPreKey);

    nlohmann::json msg;
    msg["type"]   = "KEY_INIT";
    msg["ik"]     = bytesToHex(m_ikPub);
    msg["ek"]     = bytesToHex(ephPub);
    msg["otpk"]   = bytesToHex(b.oneTimePreKey);
    msg["bundle"] = ourBundleJson();

    if (onSessionEstablished) onSessionEstablished(peerUuid);
    return msg;
}

nlohmann::json E2EManager::acceptSession(const std::string& peerUuid,
                                          const nlohmann::json& initMsg) {
    X3DHInitMessage alice;
    alice.identityKey  = bytesFromHex(initMsg.value("ik", std::string{}));
    alice.ephemeralKey = bytesFromHex(initMsg.value("ek", std::string{}));

    // Ed25519 identity-ключ инициатора приходит во вложенном бандле — сохраняем
    // для привязки в числе безопасности (иначе SPK-подпись верифицируется
    // неаутентифицированным ik_ed).
    Bytes aliceIkEd;
    if (initMsg.contains("bundle") && initMsg["bundle"].is_object() &&
        initMsg["bundle"].contains("ik_ed"))
        aliceIkEd = bytesFromHex(initMsg["bundle"]["ik_ed"].get<std::string>());

    Bytes otpkPriv;
    if (initMsg.contains("otpk")) {
        const std::string otpkHex = initMsg["otpk"].get<std::string>();
        if (!otpkHex.empty())
            otpkPriv = consumeOtpkPriv(bytesFromHex(otpkHex));
    }

    auto secret = X3DH::responderAgreement(m_ikPriv, m_spkPriv, otpkPriv, alice);
    if (!secret) {
        fprintf(stderr, "[E2E] responderAgreement failed\n");
        return nullptr;
    }

    m_peerIdentityKeys[peerUuid]   = alice.identityKey;
    m_peerIdentityEdKeys[peerUuid] = aliceIkEd;
    m_sessions[peerUuid] = DoubleRatchet::initReceiver(*secret, m_spkPriv, m_spkPub);

    if (onSessionEstablished) onSessionEstablished(peerUuid);

    nlohmann::json reply;
    reply["type"]   = "KEY_ACK";
    reply["bundle"] = ourBundleJson();
    return reply;
}

void E2EManager::processInitMessage(const std::string& peerUuid,
                                     const nlohmann::json& initMsg) {
    if (initMsg.value("type", std::string{}) == "KEY_INIT") {
        [[maybe_unused]] const auto reply = acceptSession(peerUuid, initMsg);
    }
}

// ── Per-peer mutex ─────────────────────────────────────────────────────────

std::mutex* E2EManager::mutexFor(const std::string& uuid) {
    std::lock_guard<std::mutex> mapLock(m_mapMutex);
    if (!m_sessionMutexes.count(uuid))
        m_sessionMutexes[uuid] = std::make_unique<std::mutex>();
    return m_sessionMutexes[uuid].get();
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────

nlohmann::json E2EManager::encrypt(const std::string& peerUuid, const Bytes& plaintext) {
    std::lock_guard<std::mutex> lock(*mutexFor(peerUuid));

    if (!m_sessions.count(peerUuid)) {
        fprintf(stderr, "[E2E] No session for %s\n", peerUuid.c_str());
        return nullptr;
    }

    auto& state = m_sessions[peerUuid];
    const RatchetMessage rm = DoubleRatchet::encrypt(state, plaintext);

    nlohmann::json env;
    env["type"]  = "CHAT";
    env["dh"]    = bytesToHex(rm.dhPub);
    env["n"]     = rm.msgNum;
    env["pn"]    = rm.prevChainLen;
    env["ct"]    = bytesToHex(rm.ciphertext);
    env["nonce"] = bytesToHex(rm.nonce);
    env["tag"]   = bytesToHex(rm.tag);
    return env;
}

std::expected<Bytes, std::string> E2EManager::decrypt(const std::string& peerUuid,
                                                        const nlohmann::json& envelope)
{
    std::lock_guard<std::mutex> lock(*mutexFor(peerUuid));

    if (!m_sessions.count(peerUuid)) {
        fprintf(stderr, "[E2E] No session for %s\n", peerUuid.c_str());
        return std::unexpected(std::string("no session"));
    }

    RatchetMessage rm;
    rm.dhPub        = bytesFromHex(envelope.value("dh",    std::string{}));
    rm.msgNum       = static_cast<uint32_t>(envelope.value("n", 0));
    rm.prevChainLen = static_cast<uint32_t>(envelope.value("pn", 0));
    rm.ciphertext   = bytesFromHex(envelope.value("ct",    std::string{}));
    rm.nonce        = bytesFromHex(envelope.value("nonce", std::string{}));
    rm.tag          = bytesFromHex(envelope.value("tag",   std::string{}));

    auto& state = m_sessions[peerUuid];
    auto result = DoubleRatchet::decrypt(state, rm);
    if (!result.has_value())
        fprintf(stderr, "[E2E] расшифровка провалилась (n=%u): %s\n",
                rm.msgNum, result.error().c_str());
    return result;
}

bool E2EManager::hasSession(const std::string& peerUuid) const {
    return m_sessions.count(peerUuid) > 0;
}

// ── Media Key ─────────────────────────────────────────────────────────────

Bytes E2EManager::snapshotMediaKey(const std::string& peerUuid,
                                    const std::string& callId,
                                    const Bytes& salt)
{
    std::lock_guard<std::mutex> lock(*mutexFor(peerUuid));
    const auto it = m_sessions.find(peerUuid);
    if (it == m_sessions.end() || !it->second.initialized) return {};

    // info = "naleystogramm-media-v1:" + callId + ":" + salt_hex
    const std::string saltHex = bytesToHex(salt);
    const std::string infoStr = "naleystogramm-media-v1:" + callId + ":" + saltHex;
    const Bytes info(infoStr.begin(), infoStr.end());
    return DoubleRatchet::hkdf2(it->second.rootKey, info, 32);
}

// ── Safety Numbers ────────────────────────────────────────────────────────

std::string E2EManager::getSafetyNumber(const std::string& peerUuid) const {
    if (m_ikPub.empty() || !m_peerIdentityKeys.count(peerUuid)) return {};

    // Блок каждой стороны = ik(X25519) ‖ ik_ed(Ed25519). Включение ik_ed
    // привязывает Ed25519-ключ (которым верифицируется подпись SPK) к тому же
    // ручному сравнению, что и ik — иначе SPK-подпись проверяется
    // неаутентифицированным ключом, и самосогласованный поддельный бандл
    // проходит верификацию.
    const Bytes ourBlock = m_ikPub + m_ikEdPub;

    const auto edIt = m_peerIdentityEdKeys.find(peerUuid);
    const Bytes theirBlock = (edIt != m_peerIdentityEdKeys.end())
        ? (m_peerIdentityKeys.at(peerUuid) + edIt->second)
        : m_peerIdentityKeys.at(peerUuid);

    // Канонический (отсортированный) порядок блоков ОБЯЗАТЕЛЕН: иначе Alice
    // хеширует block_A‖block_B, а Bob — block_B‖block_A, и числа безопасности
    // на двух концах никогда не совпадут — сверка против MITM становится бесполезной.
    const bool ourFirst = std::lexicographical_compare(
        ourBlock.begin(), ourBlock.end(), theirBlock.begin(), theirBlock.end());
    const Bytes combined = ourFirst ? (ourBlock + theirBlock) : (theirBlock + ourBlock);
    Bytes hash(32, 0);
    SHA256(combined.data(), combined.size(), hash.data());

    // 5 групп по 8 hex-символов (первые 20 байт = 40 hex = 5×8)
    std::string hex = bytesToHex(bytesLeft(hash, 20));
    for (char& c : hex) if (c >= 'a' && c <= 'f') c = static_cast<char>(c - 32);

    std::string result;
    for (int i = 0; i < 5; ++i) {
        if (i > 0) result += ' ';
        result += hex.substr(static_cast<size_t>(i) * 8, 8);
    }
    return result;
}

Bytes E2EManager::consumeOtpkPriv(const Bytes& pub) {
    for (size_t i = 0; i < m_otpks.size(); ++i) {
        if (m_otpks[i].second == pub) {
            const Bytes priv = m_otpks[i].first;
            m_otpks.erase(m_otpks.begin() + static_cast<ptrdiff_t>(i));
            saveKeys();
            return priv;
        }
    }
    return {};
}
