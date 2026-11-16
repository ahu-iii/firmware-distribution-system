cmake_minimum_required(VERSION 3.20)
project(firmware-distribution-system VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

option(FWDS_BUILD_TESTS "构建单元测试" ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Network Sql Widgets)

if(MSVC)
  add_compile_options(/W4 /utf-8)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
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
