#pragma once
#include <cstdint>
#include <cstddef>
#include <string_view>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/evp.h>

using Bytes = std::vector<uint8_t>;

// ── Bytes helpers (заменяют методы QByteArray) ────────────────────────────────

inline Bytes operator+(Bytes a, const Bytes& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

inline Bytes bytesLeft(const Bytes& b, std::size_t n) {
    return Bytes(b.begin(), b.begin() + std::min(n, b.size()));
}

inline Bytes bytesRight(const Bytes& b, std::size_t n) {
    if (n >= b.size()) return b;
    return Bytes(b.end() - n, b.end());
}

inline Bytes bytesMid(const Bytes& b, std::size_t pos, std::size_t len = SIZE_MAX) {
    if (pos >= b.size()) return {};
    std::size_t end = (len == SIZE_MAX) ? b.size() : std::min(pos + len, b.size());
    return Bytes(b.begin() + pos, b.begin() + end);
}

inline std::string bytesToHex(const Bytes& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t byte : b) { out += kHex[byte >> 4]; out += kHex[byte & 0xf]; }
    return out;
}

inline Bytes bytesFromHex(std::string_view hex) {
    Bytes out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
        return 0;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    return out;
}

// Строковый литерал → Bytes (без null-терминатора)
inline Bytes sv2bytes(std::string_view sv) {
    return Bytes(sv.begin(), sv.end());
}

// ── Base64 (заменяет QByteArray::toBase64/fromBase64) ─────────────────────────

inline std::string bytesToBase64(const Bytes& b) {
    if (b.empty()) return {};
    const std::size_t outLen = 4 * ((b.size() + 2) / 3);
    std::string out(outLen + 1, '\0');  // +1: EVP_EncodeBlock пишет null-терминатор
    const int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                     b.data(), static_cast<int>(b.size()));
    out.resize(static_cast<std::size_t>(len));
    return out;
}

inline Bytes bytesFromBase64(std::string_view s) {
    if (s.empty() || s.size() % 4 != 0) return {};
    Bytes out(s.size() / 4 * 3);
    const int len = EVP_DecodeBlock(out.data(),
                                     reinterpret_cast<const unsigned char*>(s.data()),
                                     static_cast<int>(s.size()));
    if (len < 0) return {};
    // EVP_DecodeBlock не учитывает '=' padding — обрезаем вручную
    std::size_t padding = 0;
    if (s.size() >= 1 && s[s.size() - 1] == '=') ++padding;
    if (s.size() >= 2 && s[s.size() - 2] == '=') ++padding;
    out.resize(static_cast<std::size_t>(len) - padding);
    return out;
}
