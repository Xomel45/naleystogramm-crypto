<div align="center">

# Naleystogramm Crypto

**E2E-криптография Naleystogramm (X3DH + Double Ratchet) — общая для desktop и Android**

</div>

---

## О проекте

Вынесено из `naleystogramm/src/crypto/` в отдельную библиотеку, чтобы desktop
(C++/Qt6) и Android (Kotlin, через будущий NDK JNI-мост) использовали **один**
код протокола вместо двух параллельных реализаций (сейчас Android дублирует
X3DH/Ratchet на Kotlin+BouncyCastle).

Код не менялся при переносе — только пути `#include` (namespaced под
`naleystogramm-crypto/...`). Логика, форматы сообщений и криптографические
константы идентичны тому, что было в `naleystogramm/src/crypto/`.

## Состав

- **X3DH** (`x3dh.h/.cpp`) — начальный обмен ключами (Curve25519/X25519 +
  Ed25519-подпись SPK)
- **Double Ratchet** (`ratchet.h/.cpp`) — forward secrecy на уровне сообщений
- **E2EManager** (`e2e.h/.cpp`) — сессии по UUID пира, персистентность
  ключей (`keys.json`, AES-256-GCM через `KeyProtector`), числа безопасности
- **KeyProtector** (`keyprotector.h/.cpp`) — мастер-ключ на диске
  (`master.key`, права 0600), HKDF-деривация дочерних ключей
- **bytes.h / securedata.h / openssl_raii.h** — общие хелперы (Bytes = `std::vector<uint8_t>`,
  hex/base64, `secureZero`, RAII-обёртки над `EVP_*`)

## Зависимости

- C++23 (`std::expected`, `std::filesystem`)
- OpenSSL (`libssl`/`libcrypto`) — обязательна
- [nlohmann/json](https://github.com/nlohmann/json) — обязательна (`e2e.h` использует `nlohmann::json` в публичном API); подхватывается через `find_package` или FetchContent
- **Никакого Qt, asio, платформенных UI-зависимостей** — переносимо на Android NDK как есть

## Сборка

Как часть desktop-проекта — `naleystogramm/CMakeLists.txt` подключает через
`add_subdirectory(../naleystogramm-crypto)` и линкует `naleystogramm-crypto`
к `naleystogramm-core`.

Отдельно:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cmake --build build --target crypto-purity   # проверка на отсутствие Qt
```

## Android (план)

Библиотека уже не содержит платформенных зависимостей, но полноценная
интеграция в `naleystogramm-mobile` не сделана в рамках этого переноса —
осознанно, т.к. замена работающей Kotlin/BouncyCastle-реализации протокола
затрагивает совместимость по сети и требует отдельной проверки формата
сообщений. Следующие шаги (не выполнены):

1. `naleystogramm-mobile/app/src/main/cpp/CMakeLists.txt` — NDK-таргет,
   `add_subdirectory()` на эту библиотеку, сборка через `externalNativeBuild`
2. OpenSSL для Android — нужна прекомпилированная статическая сборка под
   ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`) или альтернативная
   реализация (BoringSSL/aws-lc) — на десктопе используется системная/статическая
   OpenSSL, для NDK такой зависимости пока нет
3. JNI-обёртка (`E2EBridge.cpp`) поверх `E2EManager`, экспортирующая
   `init/initiateSession/acceptSession/encrypt/decrypt/getSafetyNumber` в Kotlin
4. Kotlin-сторона (`naleystogramm-mobile/.../crypto/`) переключается на JNI-мост
   вместо собственной реализации X3DH/Ratchet — **требует бинарной сверки
   протокола** (тестовый обмен сообщениями desktop↔mobile до и после переключения)
5. Только после (4) можно удалить дублирующий Kotlin-код X3DH/Ratchet
