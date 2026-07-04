#pragma once
#include <memory>
#include <openssl/evp.h>

// ── RAII-обёртки для OpenSSL контекстов ──────────────────────────────────────
//
// Используем std::unique_ptr с кастомными делитерами чтобы гарантировать
// освобождение ресурсов на всех путях выхода, включая исключения и ранние return.
// Никакого ручного EVP_*_free() — только scope-based cleanup.

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
    }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ctx) const noexcept {
        if (ctx) EVP_PKEY_CTX_free(ctx);
    }
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept {
        if (key) EVP_PKEY_free(key);
    }
};

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* ctx) const noexcept {
        if (ctx) EVP_MD_CTX_free(ctx);
    }
};

// Удобные псевдонимы типов
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using EvpPkeyCtxPtr   = std::unique_ptr<EVP_PKEY_CTX,   EvpPkeyCtxDeleter>;
using EvpPkeyPtr      = std::unique_ptr<EVP_PKEY,        EvpPkeyDeleter>;
using EvpMdCtxPtr     = std::unique_ptr<EVP_MD_CTX,      EvpMdCtxDeleter>;
