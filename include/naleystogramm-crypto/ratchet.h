#pragma once
#include "naleystogramm-crypto/bytes.h"
#include <cstdint>
#include <map>
#include <utility>
#include <expected>
#include <string>

// Double Ratchet Algorithm (per-message E2E encryption).
// After X3DH establishes a shared secret, Double Ratchet
// provides forward secrecy and break-in recovery.

static constexpr uint32_t kMaxSkippedKeys = 100;

struct RatchetState {
    Bytes    rootKey;
    Bytes    sendChainKey;
    uint32_t sendMsgNum{0};
    uint32_t prevSendMsgNum{0};
    Bytes    recvChainKey;
    uint32_t recvMsgNum{0};
    Bytes    dhPriv;
    Bytes    dhPub;
    Bytes    peerDHPub;

    // {dhPub, msgNum} → msgKey  (пропущенные сообщения)
    std::map<std::pair<Bytes, uint32_t>, Bytes> skippedKeys;

    bool initialized{false};
};

struct RatchetMessage {
    Bytes    dhPub;
    uint32_t msgNum{0};
    uint32_t prevChainLen{0};
    Bytes    ciphertext;
    Bytes    nonce;
    Bytes    tag;
};

class DoubleRatchet {
public:
    [[nodiscard]] static RatchetState initSender(const Bytes& sharedSecret,
                                                  const Bytes& peerDHPub);
    [[nodiscard]] static RatchetState initReceiver(const Bytes& sharedSecret,
                                                    const Bytes& ourDHPriv,
                                                    const Bytes& ourDHPub);

    [[nodiscard]] static RatchetMessage                     encrypt(RatchetState& state,
                                                                     const Bytes& plaintext);
    [[nodiscard]] static std::expected<Bytes, std::string>  decrypt(RatchetState& state,
                                                                     const RatchetMessage& msg);

    [[nodiscard]] static Bytes hkdf2(const Bytes& ikm, const Bytes& info, int outLen = 64);

private:
    [[nodiscard]] static Bytes chainStep(Bytes& chainKey);
    [[nodiscard]] static std::expected<Bytes, std::string> dhRatchet(
        RatchetState& state, const Bytes& peerDHPub);

    static void skipChainKeys(RatchetState& state, Bytes& chainKey,
                               const Bytes& dhPub, uint32_t& msgNum, uint32_t until);

    [[nodiscard]] static Bytes aesgcmEncrypt(const Bytes& key, const Bytes& nonce,
                                              const Bytes& plaintext, Bytes& outTag);
    [[nodiscard]] static std::expected<Bytes, std::string> aesgcmDecrypt(
        const Bytes& key, const Bytes& nonce,
        const Bytes& ciphertext, const Bytes& tag);

    [[nodiscard]] static bool  generateX25519(Bytes& priv, Bytes& pub);
    [[nodiscard]] static Bytes dh(const Bytes& priv, const Bytes& pub);
};
