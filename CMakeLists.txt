cmake_minimum_required(VERSION 3.20)
project(cvalt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY NAMES sodium libsodium)

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR
        "libsodium not found. With MSYS2 UCRT64, pass:\n"
        "  -DSODIUM_INCLUDE_DIR=C:/msys64/ucrt64/include\n"
        "  -DSODIUM_LIBRARY=C:/msys64/ucrt64/lib/libsodium.a")
endif()

add_executable(cvalt kdf.cpp vault_file.cpp main.cpp)
target_include_directories(cvalt PRIVATE ${SODIUM_INCLUDE_DIR})
target_link_libraries(cvalt PRIVATE ${SODIUM_LIBRARY})

if(MSVC)
    target_compile_options(cvalt PRIVATE /W4)
else()
    target_compile_options(cvalt PRIVATE -Wall -Wextra -Wpedantic)
endif()
