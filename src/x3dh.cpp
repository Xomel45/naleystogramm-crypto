#include "naleystogramm-crypto/x3dh.h"
#include "naleystogramm-crypto/openssl_raii.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <cstdio>

bool X3DH::generateX25519(Bytes& priv, Bytes& pub) {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
    if (!ctx) return false;
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) return false;

    EVP_PKEY* pkeyRaw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkeyRaw) <= 0) return false;
    EvpPkeyPtr pkey(pkeyRaw);

    priv.resize(32);
    pub.resize(32);
    size_t len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey.get(), priv.data(), &len) <= 0) return false;
    len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &len) <= 0) return false;
    return true;
}

Bytes X3DH::dh(const Bytes& privKey, const Bytes& peerPubKey) {
    EvpPkeyPtr priv(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
        privKey.data(), privKey.size()));
    EvpPkeyPtr pub(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
        peerPubKey.data(), peerPubKey.size()));
    if (!priv || !pub) return {};

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(priv.get(), nullptr));
    if (!ctx) return {};
    if (EVP_PKEY_derive_init(ctx.get()) <= 0) return {};
    if (EVP_PKEY_derive_set_peer(ctx.get(), pub.get()) <= 0) return {};

    size_t secretLen = 32;
    Bytes secret(32, 0);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secretLen) <= 0) return {};
    return secret;
}

Bytes X3DH::kdf(const Bytes& ikm, const Bytes& info) {
    static const Bytes kSalt(32, 0);
    static const int outLen = 32;

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx) return {};

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
        return {};
    }

    size_t outSize = static_cast<size_t>(outLen);
    if (EVP_PKEY_derive(ctx.get(), out.data(), &outSize) <= 0) {
        fprintf(stderr, "[X3DH] kdf: EVP_PKEY_derive провалился\n");
        return {};
    }
    return out;
}

Bytes X3DH::ikPrivToEdPub(const Bytes& ikPriv) {
    if (ikPriv.size() != 32) return {};

    EvpPkeyPtr edKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
        ikPriv.data(), ikPriv.size()));
    if (!edKey) return {};

    Bytes pub(32, 0);
    size_t pubLen = 32;
    if (EVP_PKEY_get_raw_public_key(edKey.get(), pub.data(), &pubLen) <= 0)
        return {};
    return pub;
}

bool X3DH::verifySpkSig(const Bytes& ikEdPub, const Bytes& spkPub, const Bytes& sig) {
    if (ikEdPub.size() != 32 || spkPub.empty() || sig.empty()) {
        fprintf(stderr, "[X3DH] verifySpkSig: некорректные аргументы\n");
        return false;
    }

    EvpPkeyPtr edKey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
        ikEdPub.data(), ikEdPub.size()));
    if (!edKey) {
        fprintf(stderr, "[X3DH] verifySpkSig: не удалось загрузить Ed25519 ключ\n");
        return false;
    }

    EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());
    if (!mdCtx) return false;

    if (EVP_DigestVerifyInit(mdCtx.get(), nullptr, nullptr, nullptr, edKey.get()) <= 0)
        return false;

    const int ret = EVP_DigestVerify(mdCtx.get(),
        sig.data(), sig.size(), spkPub.data(), spkPub.size());
    if (ret != 1) {
        fprintf(stderr, "[X3DH] Подпись SPK недействительна — возможна MITM-атака\n");
        return false;
    }
    return true;
}

Bytes X3DH::eciesDecrypt(const Bytes& localPrivKey, const Bytes& blob) {
    if (localPrivKey.size() != 32 || blob.size() < 32 + 12 + 16) {
        fprintf(stderr, "[X3DH] eciesDecrypt: недопустимый blob (size=%zu)\n", blob.size());
        return {};
    }

    const Bytes ephPub  = bytesLeft(blob, 32);
    const Bytes nonce   = bytesMid(blob, 32, 12);
    const Bytes ctTag   = bytesMid(blob, 44);
    const Bytes tag     = bytesRight(ctTag, 16);
    const Bytes ct      = bytesLeft(ctTag, ctTag.size() - 16);

    const Bytes shared  = dh(localPrivKey, ephPub);
    if (shared.empty()) { fprintf(stderr, "[X3DH] eciesDecrypt: DH провалился\n"); return {}; }

    const Bytes key = kdf(shared, sv2bytes("naleys-group-key-v1"));
    if (key.empty()) { fprintf(stderr, "[X3DH] eciesDecrypt: kdf провалился\n"); return {}; }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return {};
    Bytes plain(ct.size(), 0);
    int len = 0;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) return {};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) <= 0) return {};
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) <= 0) return {};
    if (EVP_DecryptUpdate(ctx.get(), plain.data(), &len, ct.data(),
            static_cast<int>(ct.size())) <= 0) return {};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
            const_cast<uint8_t*>(tag.data())) <= 0) return {};
    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plain.data() + len, &finalLen) <= 0) {
        fprintf(stderr, "[X3DH] eciesDecrypt: аутентификация GCM не прошла\n");
        return {};
    }
    plain.resize(static_cast<size_t>(len + finalLen));
    return plain;
}

bool X3DH::generateBundle(
    Bytes& outIKPriv, Bytes& outIKPub,
    Bytes& outSPKPriv, Bytes& outSPKPub, Bytes& outSPKSig,
    Bytes& outOTPKPriv, Bytes& outOTPKPub)
{
    if (!generateX25519(outIKPriv, outIKPub))     return false;
    if (!generateX25519(outSPKPriv, outSPKPub))   return false;
    if (!generateX25519(outOTPKPriv, outOTPKPub)) return false;

    EvpPkeyPtr edKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
        outIKPriv.data(), outIKPriv.size()));
    if (!edKey) {
        fprintf(stderr, "[X3DH] generateBundle: не удалось создать Ed25519 ключ\n");
        return false;
    }

    EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());
    if (!mdCtx) return false;

    outSPKSig.resize(64);
    size_t sigLen = 64;

    if (EVP_DigestSignInit(mdCtx.get(), nullptr, nullptr, nullptr, edKey.get()) <= 0 ||
        EVP_DigestSign(mdCtx.get(), outSPKSig.data(), &sigLen,
            outSPKPub.data(), outSPKPub.size()) <= 0)
    {
        // Fallback: нулевая подпись (не должно происходить)
        outSPKSig.assign(32, 0);
    } else {
        outSPKSig.resize(sigLen);
    }

    return true;
}

std::optional<Bytes> X3DH::initiatorAgreement(
    const Bytes& aliceIKPriv, const Bytes& /*aliceIKPub*/,
    const X3DHKeyBundle& bobBundle,
    Bytes& outEphemeralPub)
{
    if (bobBundle.ikEdPub.empty()) {
        fprintf(stderr, "[X3DH] Пир не предоставил ik_ed — сессия отклонена\n");
        return std::nullopt;
    }
    if (!verifySpkSig(bobBundle.ikEdPub, bobBundle.signedPreKey, bobBundle.signedPreKeySig)) {
        fprintf(stderr, "[X3DH] Подпись SPK недействительна — сессия отклонена\n");
        return std::nullopt;
    }

    Bytes ekPriv, ekPub;
    if (!generateX25519(ekPriv, ekPub)) return std::nullopt;
    outEphemeralPub = ekPub;

    const Bytes dh1 = dh(aliceIKPriv, bobBundle.signedPreKey);
    if (dh1.empty()) { fprintf(stderr, "[X3DH] initiator: DH1 провалился\n"); return std::nullopt; }
    const Bytes dh2 = dh(ekPriv, bobBundle.identityKey);
    if (dh2.empty()) { fprintf(stderr, "[X3DH] initiator: DH2 провалился\n"); return std::nullopt; }
    const Bytes dh3 = dh(ekPriv, bobBundle.signedPreKey);
    if (dh3.empty()) { fprintf(stderr, "[X3DH] initiator: DH3 провалился\n"); return std::nullopt; }

    Bytes ikm = dh1 + dh2 + dh3;
    if (!bobBundle.oneTimePreKey.empty()) {
        const Bytes dh4 = dh(ekPriv, bobBundle.oneTimePreKey);
        if (dh4.empty()) { fprintf(stderr, "[X3DH] initiator: DH4 провалился\n"); return std::nullopt; }
        ikm = ikm + dh4;
    }

    return kdf(ikm, sv2bytes("naleystogramm_X3DH_v1"));
}

std::optional<Bytes> X3DH::responderAgreement(
    const Bytes& bobIKPriv, const Bytes& bobSPKPriv,
    const Bytes& bobOTPKPriv,
    const X3DHInitMessage& aliceMsg)
{
    const Bytes dh1 = dh(bobSPKPriv, aliceMsg.identityKey);
    if (dh1.empty()) { fprintf(stderr, "[X3DH] responder: DH1 провалился\n"); return std::nullopt; }
    const Bytes dh2 = dh(bobIKPriv, aliceMsg.ephemeralKey);
    if (dh2.empty()) { fprintf(stderr, "[X3DH] responder: DH2 провалился\n"); return std::nullopt; }
    const Bytes dh3 = dh(bobSPKPriv, aliceMsg.ephemeralKey);
    if (dh3.empty()) { fprintf(stderr, "[X3DH] responder: DH3 провалился\n"); return std::nullopt; }

    Bytes ikm = dh1 + dh2 + dh3;
    if (!bobOTPKPriv.empty()) {
        const Bytes dh4 = dh(bobOTPKPriv, aliceMsg.ephemeralKey);
        if (dh4.empty()) { fprintf(stderr, "[X3DH] responder: DH4 провалился\n"); return std::nullopt; }
        ikm = ikm + dh4;
    }

    return kdf(ikm, sv2bytes("naleystogramm_X3DH_v1"));
}
