cmake_minimum_required(VERSION 3.20)
project(firmware-distribution-system VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

option(FWDS_BUILD_TESTS "构建单元测试" ON)

# macOS：Qt 和 OpenSSL 3 一般用 Homebrew 装。openssl@3 是 keg-only（不链接进 /opt/homebrew，
# 避免和系统自带的 LibreSSL 混淆），CMake 默认找不到，这里用 brew --prefix 问出安装位置。
# 命令行已经用 -DCMAKE_PREFIX_PATH / -DOPENSSL_ROOT_DIR 指定了的，以命令行为准；不用 Homebrew 时什么也不做。
if(APPLE)
  find_program(FWDS_BREW brew)
  if(FWDS_BREW)
    foreach(formula qt openssl@3)
      execute_process(COMMAND ${FWDS_BREW} --prefix ${formula}
                      OUTPUT_VARIABLE prefix OUTPUT_STRIP_TRAILING_WHITESPACE
                      RESULT_VARIABLE result ERROR_QUIET)
      if(result EQUAL 0 AND EXISTS "${prefix}")
        if(formula STREQUAL "openssl@3" AND NOT OPENSSL_ROOT_DIR)
          set(OPENSSL_ROOT_DIR "${prefix}")
        elseif(formula STREQUAL "qt")
          list(APPEND CMAKE_PREFIX_PATH "${prefix}")
        endif()
      endif()
    endforeach()
  endif()
endif()

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Network Sql Widgets)

if(MSVC)
  add_compile_options(/W4 /utf-8)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
  # Qt 的 qCWarning 等日志宏在 clang（含 macOS 的 Apple Clang）+ -Wpedantic 下每处都报这一条，
  # 是 Qt 头文件的写法而不是本项目代码的问题，关掉以免淹没真正的警告
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wno-gnu-zero-variadic-macro-arguments)
  endif()
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(common)
add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(signer)

if(FWDS_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
