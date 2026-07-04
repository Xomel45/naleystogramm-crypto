cmake_minimum_required(VERSION 3.22)
project(naleystogramm-crypto VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Библиотека не тянет Qt/asio — только OpenSSL + nlohmann/json + std.
# Собирается как отдельный проект (ctest'ы) или как add_subdirectory()
# из наleystogramm (desktop) / внешнего NDK-таргета (Android).

if(WIN32)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL REQUIRED)

include(FetchContent)
find_package(nlohmann_json QUIET CONFIG)
if(nlohmann_json_FOUND)
    message(STATUS "naleystogramm-crypto: nlohmann/json системный (${nlohmann_json_VERSION})")
else()
    FetchContent_Declare(nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
    message(STATUS "naleystogramm-crypto: nlohmann/json FetchContent v3.11.3")
endif()

add_library(naleystogramm-crypto STATIC
    include/naleystogramm-crypto/bytes.h
    include/naleystogramm-crypto/securedata.h
    include/naleystogramm-crypto/openssl_raii.h
    include/naleystogramm-crypto/keyprotector.h
    src/keyprotector.cpp
    include/naleystogramm-crypto/x3dh.h
    src/x3dh.cpp
    include/naleystogramm-crypto/ratchet.h
    src/ratchet.cpp
    include/naleystogramm-crypto/e2e.h
    src/e2e.cpp
)

# PUBLIC: e2e.h выставляет nlohmann::json в своём API (ourBundleJson/encrypt/
# decrypt принимают/возвращают nlohmann::json) — любой потребитель библиотеки
# должен получить include-путь nlohmann транзитивно.
target_include_directories(naleystogramm-crypto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_link_libraries(naleystogramm-crypto PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# ── Самопроверка: библиотека не должна знать о Qt ────────────────────────────
add_custom_target(crypto-purity
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan
        "=== Проверка Qt-зависимостей в naleystogramm-crypto ==="
    COMMAND bash -c
        "violations=\$(grep -rn --include='*.h' --include='*.cpp' \
            -e '#include <Q' -e '#include \"Q' \
            ${CMAKE_CURRENT_SOURCE_DIR}/include/ ${CMAKE_CURRENT_SOURCE_DIR}/src/); \
         if [ -n \"\$violations\" ]; then \
           echo ''; echo 'НАРУШЕНИЯ — Qt в naleystogramm-crypto:'; \
           echo \"\$violations\"; exit 1; \
         else \
           echo 'Чисто — Qt не найден'; \
         fi"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Проверка отсутствия Qt в naleystogramm-crypto"
    VERBATIM
)
