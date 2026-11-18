cmake_minimum_required(VERSION 3.20)
project(firmware-distribution-system VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

option(FWDS_BUILD_TESTS "构建单元测试" ON)
option(FWDS_BUILD_DEMO "构建答辩演示的数据准备工具 fwds-demo-seed（不随安装包发布）" ON)
# 程序版本（设计 8.4 节“版本标识”）：默认取上面 project() 里的版本。
# 升级回滚演练时要有新旧两个版本，可以在配置时用 -DFWDS_VERSION=0.2.1 另编一份
set(FWDS_VERSION "${PROJECT_VERSION}" CACHE STRING "程序版本 主.次.修订")
# 发布版强制程序自校验（设计第 15 节）：打开后，可执行文件旁边没有签名文件 <程序>.sig 就拒绝运行。
# 开发版每次编译程序都会变，默认不强制：有签名文件就校验（不符同样拒绝运行），没有只警告
option(FWDS_REQUIRE_EXE_SIGNATURE "缺少程序签名时拒绝运行（发布版打开）" OFF)

# macOS：Qt 和 OpenSSL 一般用 Homebrew 装，这里用 brew --prefix 问出安装位置。
# 本程序必须和 Qt 的 TLS 后端用同一版 OpenSSL（一个进程里不能混两版 libcrypto），所以不写死 openssl@3，
# 而是看 Qt 的 TLS 插件实际链接的是哪一份 libcrypto（Homebrew 的 Qt 6.12 起改用 openssl@4），就用那一份。
# 这些 OpenSSL 都是 keg-only（不链接进 /opt/homebrew），CMake 默认找不到，也和 brew link 了哪一版无关。
# 命令行已经用 -DCMAKE_PREFIX_PATH / -DOPENSSL_ROOT_DIR 指定了的，以命令行为准；不用 Homebrew 时什么也不做。
if(APPLE)
  find_program(FWDS_BREW brew)
  if(FWDS_BREW)
    execute_process(COMMAND ${FWDS_BREW} --prefix qt
                    OUTPUT_VARIABLE prefix OUTPUT_STRIP_TRAILING_WHITESPACE
                    RESULT_VARIABLE result ERROR_QUIET)
    if(result EQUAL 0 AND EXISTS "${prefix}")
      list(APPEND CMAKE_PREFIX_PATH "${prefix}")
    endif()

    if(NOT OPENSSL_ROOT_DIR)
      # Qt 的 TLS 插件在 qtbase 里，用 otool -L 列出它依赖的动态库，取出 libcrypto 所在的目录
      execute_process(COMMAND ${FWDS_BREW} --prefix qtbase
                      OUTPUT_VARIABLE qtbase OUTPUT_STRIP_TRAILING_WHITESPACE
                      RESULT_VARIABLE result ERROR_QUIET)
      set(plugin "${qtbase}/share/qt/plugins/tls/libqopensslbackend.dylib")
      if(result EQUAL 0 AND EXISTS "${plugin}")
        execute_process(COMMAND otool -L "${plugin}" OUTPUT_VARIABLE deps ERROR_QUIET)
        # 例如 “/opt/homebrew/opt/openssl@4/lib/libcrypto.4.dylib”，取 lib 的上一级目录
        if(deps MATCHES "[ \t\n](/[^ \t\n]+)/lib/libcrypto[.0-9]*\.dylib")
          set(OPENSSL_ROOT_DIR "${CMAKE_MATCH_1}")
          message(STATUS "Qt 的 TLS 插件用的 OpenSSL 在 ${OPENSSL_ROOT_DIR}，本程序也用它")
        endif()
      endif()
    endif()

    # 找不到插件（例如只装了 Qt 官方安装器的版本）时，退回 openssl@3
    if(NOT OPENSSL_ROOT_DIR)
      execute_process(COMMAND ${FWDS_BREW} --prefix openssl@3
                      OUTPUT_VARIABLE prefix OUTPUT_STRIP_TRAILING_WHITESPACE
                      RESULT_VARIABLE result ERROR_QUIET)
      if(result EQUAL 0 AND EXISTS "${prefix}")
        set(OPENSSL_ROOT_DIR "${prefix}")
      endif()
    endif()
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

if(FWDS_BUILD_DEMO)
  add_subdirectory(demo)
endif()

if(FWDS_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
