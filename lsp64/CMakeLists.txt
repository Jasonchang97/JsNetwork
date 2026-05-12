cmake_minimum_required(VERSION 3.14)
project(jsnetwork_lsp64 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS _WINSOCK_DEPRECATED_NO_WARNINGS)
endif()

set(PARENT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

# 64-bit LSP DLL - no Qt dependency, plain Win32 DLL
add_library(jsnetwork_lsp SHARED
    ${PARENT_DIR}/src/injector/lsp_provider.cpp
    ${PARENT_DIR}/src/injector/lsp_provider.h
    ${PARENT_DIR}/src/injector/jsnetwork_lsp.def
)
target_link_libraries(jsnetwork_lsp PRIVATE ws2_32)
target_include_directories(jsnetwork_lsp PRIVATE ${PARENT_DIR}/src)
set_target_properties(jsnetwork_lsp PROPERTIES OUTPUT_NAME "jsnetwork_lsp")

# 64-bit LSP Installer
add_executable(lsp_installer64 ${PARENT_DIR}/src/injector/lsp_installer.cpp)
target_link_libraries(lsp_installer64 PRIVATE ws2_32 advapi32 sporder)
set_target_properties(lsp_installer64 PROPERTIES OUTPUT_NAME "lsp_installer64")
