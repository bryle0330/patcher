cmake_minimum_required(VERSION 3.10)
project(patcher)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(patcher
    src/main.c
    src/pe_parser.c
    src/obfuscator.c
    src/stub_generator.c
)

target_include_directories(patcher PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)