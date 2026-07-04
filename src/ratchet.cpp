#include "naleystogramm-crypto/ratchet.h"
#include "naleystogramm-crypto/openssl_raii.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstdio>

static void logOpenSSLError(const char* where) {
    const unsigned long err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    fprintf(stderr, "[Ratchet] OpenSSL error in %s: %s (code: %lu)\n", where, buf, err);
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────

Bytes DoubleRatchet::aesgcmEncrypt(const Bytes& key, const Bytes& nonce,
                                    const Bytes& plaintext, Bytes& outTag) {
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) { logOpenSSLError("aesgcmEncrypt/new"); return {}; }

    Bytes ciphertext(plaintext.size(), 0);
    outTag.resize(16);
    int len = 0;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) {
        logOpenSSLError("aesgcmEncrypt/Init"); return {};
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) <= 0) {
        logOpenSSLError("aesgcmEncrypt/IVLEN"); return {};
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) <= 0) {
        logOpenSSLError("aesgcmEncrypt/KeyNonce"); return {};
    }
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
            plaintext.data(), static_cast<int>(plaintext.size())) <= 0) {
        logOpenSSLError("aesgcmEncrypt/Update"); return {};
    }
    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &finalLen) <= 0) {
        logOpenSSLError("aesgcmEncrypt/Final"); return {};
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, outTag.data()) <= 0) {
        logOpenSSLError("aesgcmEncrypt/GetTag"); return {};
    }
    return ciphertext;
}

std::expected<Bytes, std::string> DoubleRatchet::aesgcmDecrypt(
    const Bytes& key, const Bytes& nonce,
    const Bytes& ciphertext, const Bytes& tag)
{
    // Длины nonce/tag/key приходят из сети (hex-декод envelope) без проверки на
    // вызывающей стороне. OpenSSL читает фиксированные 12 (IV) и 16 (tag) байт из
    // буфера независимо от его реального размера — короткий nonce/tag даёт
    // out-of-bounds read. Валидируем до любого EVP-вызова.
    if (key.size() != 32 || nonce.size() != 12 || tag.size() != 16)
        return std::unexpected(std::string("aesgcmDecrypt: неверная длина key/nonce/tag"));

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return std::unexpected(std::string("EVP_CIPHER_CTX_new failed"));

    Bytes plaintext(ciphertext.size(), 0);
    int len = 0;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) {
        logOpenSSLError("aesgcmDecrypt/Init");
        return std::unexpected(std::string("EVP_DecryptInit_ex failed"));
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) <= 0) {
        logOpenSSLError("aesgcmDecrypt/IVLEN");
        return std::unexpected(std::string("EVP_CTRL_GCM_SET_IVLEN failed"));
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) <= 0) {
        logOpenSSLError("aesgcmDecrypt/KeyNonce");
        return std::unexpected(std::string("EVP_DecryptInit_ex KeyNonce failed"));
    }
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
            ciphertext.data(), static_cast<int>(ciphertext.size())) <= 0) {
        logOpenSSLError("aesgcmDecrypt/Update");
        return std::unexpected(std::string("EVP_DecryptUpdate failed"));
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
            const_cast<uint8_t*>(tag.data())) <= 0) {
        logOpenSSLError("aesgcmDecrypt/SetTag");
        return std::unexpected(std::string("EVP_CTRL_GCM_SET_TAG failed"));
    }
    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &finalLen) <= 0) {
        fprintf(stderr, "[Ratchet] GCM auth tag mismatch\n");
        return std::unexpected(std::string("GCM authentication failed"));
    }
    return plaintext;
}

// ── X25519 ────────────────────────────────────────────────────────────────

bool DoubleRatchet::generateX25519(Bytes& priv, Bytes& pub) {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
    if (!ctx) { logOpenSSLError("generateX25519/ctx_new"); return false; }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        logOpenSSLError("generateX25519/keygen_init"); return false;
    }
    EVP_PKEY* pkeyRaw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkeyRaw) <= 0) {
        logOpenSSLError("generateX25519/keygen"); return false;
    }
    EvpPkeyPtr pkey(pkeyRaw);

    priv.resize(32);
    pub.resize(32);
    size_t len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey.get(), priv.data(), &len) <= 0) {
        logOpenSSLError("generateX25519/get_priv"); return false;
    }
    len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &len) <= 0) {
        logOpenSSLError("generateX25519/get_pub"); return false;
    }
    return true;
}

Bytes DoubleRatchet::dh(const Bytes& priv, const Bytes& pub) {
    // pub — публичный DH-ключ пира из сети (msg.dhPub). Ниже жёстко передаём 32 в
    // EVP_PKEY_new_raw_public_key, поэтому короткий буфер → out-of-bounds read.
    if (priv.size() != 32 || pub.size() != 32) {
        fprintf(stderr, "[Ratchet] dh: неверная длина ключа (priv=%zu pub=%zu)\n",
                priv.size(), pub.size());
        return {};
    }
    EvpPkeyPtr pk(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), 32));
    EvpPkeyPtr pp(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pub.data(), 32));
    if (!pk || !pp) { logOpenSSLError("dh/new_key"); return {}; }

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(pk.get(), nullptr));
    if (!ctx) { logOpenSSLError("dh/ctx_new"); return {}; }
    if (EVP_PKEY_derive_init(ctx.get()) <= 0) { logOpenSSLError("dh/derive_init"); return {}; }
    if (EVP_PKEY_derive_set_peer(ctx.get(), pp.get()) <= 0) { logOpenSSLError("dh/set_peer"); return {}; }

    size_t secretLen = 32;
    Bytes secret(32, 0);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secretLen) <= 0) {
        logOpenSSLError("dh/derive"); return {};
    }
    return secret;
}

// ── HKDF ──────────────────────────────────────────────────────────────────

Bytes DoubleRatchet::hkdf2(const Bytes& ikm, const Bytes& info, int outLen) {
    static const Bytes kSalt(32, 0);

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx) { logOpenSSLError("hkdf2/ctx_new"); return {}; }

    Bytes out(static_cast<size_t>(outLen), 0);

    if (EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), kSalt.data(),
            static_cast<int>(kSalt.size())) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(),
            static_cast<int>(ikm.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(),
            static_cast<int>(info.size())) <= 0)
    {
        logOpenSSLError("hkdf2/setup"); return {};
    }

    size_t s = static_cast<size_t>(outLen);
    if (EVP_PKEY_derive(ctx.get(), out.data(), &s) <= 0) {
        logOpenSSLError("hkdf2/derive"); return {};
    }
    return out;
}

// ── Chain step ────────────────────────────────────────────────────────────

Bytes DoubleRatchet::chainStep(Bytes& chainKey) {
    const Bytes derived = hkdf2(chainKey, sv2bytes("MsgKey"), 64);
    chainKey = bytesLeft(derived, 32);
    return bytesRight(derived, 32);
}

// ── Skip keys ─────────────────────────────────────────────────────────────

void DoubleRatchet::skipChainKeys(RatchetState& state, Bytes& chainKey,
                                   const Bytes& dhPub, uint32_t& msgNum, uint32_t until) {
    if (until <= msgNum) return;
    if (until - msgNum > kMaxSkippedKeys) {
        fprintf(stderr, "[Ratchet] skipChainKeys: пропуск %u→%u превышает лимит\n", msgNum, until);
        until = msgNum + kMaxSkippedKeys;
    }
    while (msgNum < until) {
        if (state.skippedKeys.size() >= kMaxSkippedKeys) {
            fprintf(stderr, "[Ratchet] skipChainKeys: буфер переполнен\n");
            break;
        }
        state.skippedKeys[{dhPub, msgNum}] = chainStep(chainKey);
        ++msgNum;
    }
}

// ── DH ratchet ────────────────────────────────────────────────────────────

std::expected<Bytes, std::string> DoubleRatchet::dhRatchet(RatchetState& state,
                                                             const Bytes& peerDHPub) {
    const Bytes dhOut1 = dh(state.dhPriv, peerDHPub);
    if (dhOut1.empty()) return std::unexpected("dhRatchet: DH(1) провалился");

    const Bytes derived1 = hkdf2(state.rootKey + dhOut1, sv2bytes("RatchetStep"), 64);
    if (derived1.empty()) return std::unexpected("dhRatchet: HKDF(1) провалился");

    Bytes newDHPriv, newDHPub;
    if (!generateX25519(newDHPriv, newDHPub))
        return std::unexpected("dhRatchet: generateX25519 провалился");

    const Bytes dhOut2 = dh(newDHPriv, peerDHPub);
    if (dhOut2.empty()) return std::unexpected("dhRatchet: DH(2) провалился");

    const Bytes derived2 = hkdf2(bytesLeft(derived1, 32) + dhOut2, sv2bytes("RatchetStep"), 64);
    if (derived2.empty()) return std::unexpected("dhRatchet: HKDF(2) провалился");

    state.rootKey      = bytesLeft(derived2, 32);
    state.sendChainKey = bytesRight(derived2, 32);
    state.peerDHPub    = peerDHPub;
    state.dhPriv       = newDHPriv;
    state.dhPub        = newDHPub;

    return bytesRight(derived1, 32); // ckr
}

// ── Init ──────────────────────────────────────────────────────────────────

RatchetState DoubleRatchet::initSender(const Bytes& sharedSecret, const Bytes& peerDHPub) {
    RatchetState s;
    s.rootKey   = sharedSecret;
    s.peerDHPub = peerDHPub;

    if (!generateX25519(s.dhPriv, s.dhPub)) {
        fprintf(stderr, "[Ratchet] initSender: не удалось сгенерировать DH-пару\n");
        return s;
    }

    const Bytes dhOut = dh(s.dhPriv, peerDHPub);
    if (dhOut.empty()) { fprintf(stderr, "[Ratchet] initSender: DH провалился\n"); return s; }

    const Bytes derived = hkdf2(s.rootKey + dhOut, sv2bytes("RatchetStep"), 64);
    if (derived.empty()) { fprintf(stderr, "[Ratchet] initSender: HKDF провалился\n"); return s; }

    s.rootKey      = bytesLeft(derived, 32);
    s.sendChainKey = bytesRight(derived, 32);
    s.initialized  = true;
    return s;
}

RatchetState DoubleRatchet::initReceiver(const Bytes& sharedSecret,
                                          const Bytes& ourDHPriv, const Bytes& ourDHPub) {
    RatchetState s;
    s.rootKey     = sharedSecret;
    s.dhPriv      = ourDHPriv;
    s.dhPub       = ourDHPub;
    s.initialized = true;
    return s;
}

// ── Encrypt ───────────────────────────────────────────────────────────────

RatchetMessage DoubleRatchet::encrypt(RatchetState& state, const Bytes& plaintext) {
    if (!state.initialized) {
        fprintf(stderr, "[Ratchet] encrypt: неинициализированный state\n");
        return {};
    }

    const Bytes msgKey = chainStep(state.sendChainKey);
    const Bytes aesKey = bytesLeft(msgKey, 32);

    Bytes nonce(12, 0);
    if (RAND_bytes(nonce.data(), 12) != 1) {
        fprintf(stderr, "[Ratchet] encrypt: RAND_bytes провалился\n");
        return {};
    }

    RatchetMessage msg;
    msg.dhPub        = state.dhPub;
    msg.msgNum       = state.sendMsgNum++;
    msg.prevChainLen = state.prevSendMsgNum;
    msg.nonce        = nonce;
    msg.ciphertext   = aesgcmEncrypt(aesKey, nonce, plaintext, msg.tag);
    return msg;
}

// ── Decrypt ───────────────────────────────────────────────────────────────

std::expected<Bytes, std::string> DoubleRatchet::decrypt(
    RatchetState& state, const RatchetMessage& msg)
{
    // Все изменения проводим на копии state и коммитим ТОЛЬКО после успешной
    // аутентификации GCM. Иначе инъекция одного фрейма с произвольным dhPub
    // (MITM в сети) необратимо продвигает храповик до проверки тега и навсегда
    // рассинхронизирует сессию — перманентный DoS.
    RatchetState working = state;

    // Проверяем кеш пропущенных ключей
    const std::pair<Bytes, uint32_t> skippedKey{msg.dhPub, msg.msgNum};
    const auto it = working.skippedKeys.find(skippedKey);
    if (it != working.skippedKeys.end()) {
        const Bytes msgKey = it->second;
        auto plaintext = aesgcmDecrypt(bytesLeft(msgKey, 32), msg.nonce,
                                       msg.ciphertext, msg.tag);
        if (!plaintext) return plaintext;   // провал аутентификации — state нетронут
        working.skippedKeys.erase(skippedKey);
        state = std::move(working);
        return plaintext;
    }

    // Новый DH-ключ собеседника → шаг DH-храповика
    if (msg.dhPub != working.peerDHPub) {
        const Bytes oldDHPub = working.peerDHPub;
        skipChainKeys(working, working.recvChainKey, oldDHPub,
                      working.recvMsgNum, msg.prevChainLen);

        working.prevSendMsgNum = working.sendMsgNum;
        working.sendMsgNum     = 0;

        auto ckrResult = dhRatchet(working, msg.dhPub);
        if (!ckrResult) return std::unexpected(ckrResult.error());

        working.recvChainKey = ckrResult.value();
        working.recvMsgNum   = 0;

        skipChainKeys(working, working.recvChainKey, msg.dhPub,
                      working.recvMsgNum, msg.msgNum);
    } else {
        skipChainKeys(working, working.recvChainKey, msg.dhPub,
                      working.recvMsgNum, msg.msgNum);
    }

    const Bytes msgKey = chainStep(working.recvChainKey);
    working.recvMsgNum++;
    auto plaintext = aesgcmDecrypt(bytesLeft(msgKey, 32), msg.nonce,
                                   msg.ciphertext, msg.tag);
    if (!plaintext) return plaintext;       // провал аутентификации — state нетронут
    state = std::move(working);
    return plaintext;
}
