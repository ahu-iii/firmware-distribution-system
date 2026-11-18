find_package(OpenSSL 3.0 REQUIRED)

add_library(fwds_common STATIC
  protocol.h
  protocol.cpp
  frame_codec.h
  frame_codec.cpp
  manifest.h
  manifest.cpp
  firmware_package.h
  firmware_package.cpp
  firmware_image.h
  firmware_image.cpp
  update_messages.h
  update_messages.cpp
  config.h
  config.cpp
  log.h
  log.cpp
  crypto/secure_buffer.h
  crypto/openssl_util.h
  crypto/openssl_util.cpp
  crypto/rand.h
  crypto/rand.cpp
  crypto/aead_gcm.h
  crypto/aead_gcm.cpp
  crypto/sha256.h
  crypto/sha256.cpp
  crypto/rsa_pss.h
  crypto/rsa_pss.cpp
  crypto/kdf.h
  crypto/kdf.cpp
  crypto/key_file.h
  crypto/key_file.cpp
  crypto/x509_util.h
  crypto/x509_util.cpp
  net/backoff.h
  net/channel_security.h
  net/frame_channel.h
  net/frame_channel.cpp
  security/cert_verifier.h
  security/cert_verifier.cpp
  security/manifest_verifier.h
  security/manifest_verifier.cpp
  security/fsk_public_key.h
  security/fsk_public_key.cpp
  security/key_store.h
  security/key_store.cpp
  security/tls_channel.h
  security/tls_channel.cpp
  security/license.h
  security/license.cpp
  security/exe_signature.h
  security/exe_signature.cpp
  obfuscated_string.h
  shutdown_signal.h
  shutdown_signal.cpp
)
target_include_directories(fwds_common PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(fwds_common PUBLIC Qt6::Core Qt6::Network OpenSSL::Crypto)

if(FWDS_REQUIRE_EXE_SIGNATURE)
  set(FWDS_REQUIRE_EXE_SIGNATURE_BOOL true)
else()
  set(FWDS_REQUIRE_EXE_SIGNATURE_BOOL false)
endif()
# 版本号和发布版开关写进生成的头文件 build_info.h，三个程序和“关于”信息都从这里取
configure_file(build_info.h.in ${CMAKE_BINARY_DIR}/generated/common/build_info.h @ONLY)
target_include_directories(fwds_common PUBLIC ${CMAKE_BINARY_DIR}/generated)
