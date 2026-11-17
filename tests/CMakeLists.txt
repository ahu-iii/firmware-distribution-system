# 优先用系统安装的 GoogleTest，没有就在线拉取
find_package(GTest QUIET)
if(NOT GTest_FOUND)
  include(FetchContent)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()

add_executable(fwds-tests
  main.cpp
  test_util.h
  test_frame_codec.cpp
  test_backoff.cpp
  test_config.cpp
  test_conn_limiter.cpp
  test_network.cpp
  test_pki.h
  test_crypto.cpp
  test_cert_verifier.cpp
  test_ca_store.cpp
  test_tls.cpp
  test_server_env.h
  test_operator_auth.cpp
  test_device_registry.cpp
  test_admin_service.cpp
  test_login_throttle.cpp
  test_device_login.cpp
  test_fsk.h
  test_rsa_pss.cpp
  test_manifest.cpp
  test_manifest_verifier.cpp
  test_firmware_package.cpp
  test_update_validator.cpp
  test_update_messages.cpp
  test_resume_store.cpp
  test_downloader.cpp
  test_chunk_download.cpp
  test_device.h
  test_boot_storage.cpp
  test_anti_rollback.cpp
  test_bootloader.cpp
  test_updater.cpp
)
target_link_libraries(fwds-tests PRIVATE fwds_server_lib fwds_client_lib fwds_signer_lib GTest::gtest)

include(GoogleTest)
gtest_discover_tests(fwds-tests)
target_compile_definitions(fwds-tests PRIVATE FWDS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
