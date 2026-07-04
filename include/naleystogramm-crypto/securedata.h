#pragma once
#include "naleystogramm-crypto/bytes.h"
#include <openssl/crypto.h>

// Безопасное обнуление ключевого материала.
// OPENSSL_cleanse() выполняет гарантированную запись нулей,
// которую компилятор не оптимизирует (в отличие от memset/fill).

inline void secureZero(Bytes& data) {
    if (!data.empty())
        OPENSSL_cleanse(data.data(), data.size());
    data.clear();
}
