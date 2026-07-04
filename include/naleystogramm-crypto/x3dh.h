#pragma once
#include "naleystogramm-crypto/bytes.h"
#include <optional>

// X3DH (Extended Triple Diffie-Hellman) key agreement.
// All keys are Curve25519 (X25519) via OpenSSL EVP_PKEY.

struct X3DHKeyBundle {
    Bytes identityKey;      // IK pub (32 bytes, raw X25519)
    Bytes ikEdPub;          // Ed25519 pub для верификации SPK подписи
    Bytes signedPreKey;     // SPK pub
    Bytes signedPreKeySig;  // Ed25519 подпись SPK
    Bytes oneTimePreKey;    // OPK pub (may be empty)
};

struct X3DHInitMessage {
    Bytes identityKey;      // IK_A pub
    Bytes ephemeralKey;     // EK_A pub
    Bytes usedOtpkId;       // which OPK was consumed (hex id)
    Bytes initialCiphertext;
};

class X3DH {
public:
    [[nodiscard]] static bool generateBundle(
        Bytes& outIdentityPriv, Bytes& outIdentityPub,
        Bytes& outSignedPrePriv, Bytes& outSignedPrePub,
        Bytes& outSignedPreSig,
        Bytes& outOtpkPriv, Bytes& outOtpkPub);

    [[nodiscard]] static std::optional<Bytes> initiatorAgreement(
        const Bytes& aliceIKPriv, const Bytes& aliceIKPub,
        const X3DHKeyBundle& bobBundle,
        Bytes& outEphemeralPub);

    [[nodiscard]] static std::optional<Bytes> responderAgreement(
        const Bytes& bobIKPriv, const Bytes& bobSPKPriv,
        const Bytes& bobOTPKPriv,
        const X3DHInitMessage& aliceMsg);

    [[nodiscard]] static Bytes ikPrivToEdPub(const Bytes& ikPriv);
    [[nodiscard]] static bool  verifySpkSig(const Bytes& ikEdPub,
                                             const Bytes& spkPub,
                                             const Bytes& sig);

    // ECIES decrypt: ephemeral_pub(32) || nonce(12) || ciphertext+tag(N+16)
    [[nodiscard]] static Bytes eciesDecrypt(const Bytes& localPrivKey,
                                             const Bytes& encryptedBlob);

    [[nodiscard]] static bool generateX25519(Bytes& priv, Bytes& pub);

private:
    [[nodiscard]] static Bytes dh(const Bytes& privKey, const Bytes& peerPubKey);
    [[nodiscard]] static Bytes kdf(const Bytes& ikm, const Bytes& info);
};
