# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: GPL-3.0-or-later
#
# libyasvara_xposed.so: the native half of the ROM-integrated Vector (LSPlant based) Xposed
# runtime. Built out of tree by build.sh with the NDK because LSPlant and its dex builder are
# C++20 modules, which Soong cannot compile. The result is checked in under ../prebuilt/.
cmake_minimum_required(VERSION 3.28)
project(yasvara_xposed LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(VECTOR_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(third_party)

file(GLOB_RECURSE VECTOR_SOURCES "vector/src/*.cpp")
add_library(vector_native STATIC ${VECTOR_SOURCES})
target_include_directories(vector_native PUBLIC vector/include)
target_include_directories(vector_native PRIVATE vector/src third_party/xz-embedded/linux/include)
target_compile_definitions(vector_native PUBLIC
    VERSION_CODE=${YASVARA_XPOSED_VERSION_CODE} VERSION_NAME="${YASVARA_XPOSED_VERSION_NAME}")
target_compile_options(vector_native PRIVATE
    -Wno-c99-extensions -Wno-extra-semi -Wno-gnu-flexible-array-initializer
    -Wno-gnu-string-literal-operator-template -Wno-gnu-zero-variadic-macro-arguments
    -Wno-variadic-macros -Wno-zero-length-array)
target_link_libraries(vector_native PUBLIC dobby_static lsplant_static xz_static log fmt-header-only)
target_link_libraries(vector_native PRIVATE dex_builder_static)

add_library(yasvara_xposed SHARED src/seam.cpp)
target_include_directories(yasvara_xposed PRIVATE src)
target_link_libraries(yasvara_xposed PRIVATE vector_native log)
# Only the seam entry point is part of the ABI; keep every other symbol (LSPlant, Dobby, fmt...)
# out of the dynamic symbol table so nothing in the app process can bind to them by name.
set_target_properties(yasvara_xposed PROPERTIES
    CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
target_link_options(yasvara_xposed PRIVATE -Wl,--exclude-libs,ALL -Wl,--gc-sections
    -Wl,-z,max-page-size=16384 -Wl,--build-id=none)
