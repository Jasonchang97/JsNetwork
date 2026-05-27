cmake_minimum_required(VERSION 3.14)
project(JsNetwork VERSION 1.0.2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Platform-specific paths (overridable via -D flags)
if(WIN32)
    # MSVC UTF-8 source encoding
    if(MSVC)
        add_compile_options(/utf-8)
        add_compile_definitions(_CRT_SECURE_NO_WARNINGS _WINSOCK_DEPRECATED_NO_WARNINGS)
    endif()

    set(QT5_DIR "" CACHE PATH "Path to Qt5 installation root (e.g. C:/Qt/5.15.2/msvc2019)")
    set(VCPKG_LIB_DIR "" CACHE PATH "Path to vcpkg installed libraries")
    set(OPENSSL_DIR "" CACHE PATH "Path to OpenSSL installation")
    set(NPCAP_SDK_DIR "" CACHE PATH "Path to Npcap SDK")
else()
    set(QT5_DIR "" CACHE PATH "Path to Qt5 installation root")
    set(OPENSSL_DIR "" CACHE PATH "Path to OpenSSL installation")
    set(PCAP_DIR "" CACHE PATH "Path to libpcap installation")
endif()

# Find Qt5 - use custom path if provided, otherwise auto-detect
if(QT5_DIR)
    set(CMAKE_PREFIX_PATH "${QT5_DIR}")
endif()
find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets Network Sql)

set(SOURCES
    src/main.cpp
    src/app/application.cpp
    src/app/translator.cpp
    src/core/proxy_server.cpp
    src/core/http_parser.cpp
    src/core/http2_parser.cpp
    src/core/websocket_parser.cpp
    src/core/cert_manager.cpp
    src/core/mitm_engine.cpp
    src/core/mock_engine.cpp
    src/core/breakpoint_engine.cpp
    src/core/traffic_storage.cpp
    src/core/har_exporter.cpp
    src/model/request_item.cpp
    src/ui/mainwindow.cpp
    src/ui/trafficlistwidget.cpp
    src/ui/detailpanel.cpp
    src/ui/bodypreview.cpp
    src/ui/timelinewidget.cpp
    src/ui/mockpanel.cpp
    src/ui/composerwidget.cpp
    src/ui/theme.cpp
    src/platform/proxy_config.cpp
    src/platform/cert_installer.cpp
    src/core/packet_capture.cpp
)

set(HEADERS
    src/app/application.h
    src/app/translator.h
    src/core/proxy_server.h
    src/core/http_parser.h
    src/core/http2_parser.h
    src/core/websocket_parser.h
    src/core/cert_manager.h
    src/core/mitm_engine.h
    src/core/mock_engine.h
    src/core/breakpoint_engine.h
    src/core/traffic_storage.h
    src/core/har_exporter.h
    src/model/request_item.h
    src/ui/mainwindow.h
    src/ui/trafficlistwidget.h
    src/ui/detailpanel.h
    src/ui/bodypreview.h
    src/ui/timelinewidget.h
    src/ui/mockpanel.h
    src/ui/composerwidget.h
    src/ui/theme.h
    src/platform/proxy_config.h
    src/platform/cert_installer.h
    src/core/packet_capture.h
)

# App icon (macOS)
if(APPLE)
    set(APP_ICON "${CMAKE_CURRENT_SOURCE_DIR}/resources/icons/AppIcon.icns")
    if(EXISTS "${APP_ICON}")
        set(ICON_RESOURCE "${APP_ICON}")
        set_source_files_properties(${APP_ICON} PROPERTIES
            MACOSX_PACKAGE_LOCATION "Resources"
        )
    else()
        set(ICON_RESOURCE "")
    endif()
endif()

# Windows app icon
if(WIN32)
    set(APP_ICON_RC "${CMAKE_CURRENT_SOURCE_DIR}/resources/app.rc")
    if(EXISTS "${APP_ICON_RC}")
        list(APPEND SOURCES ${APP_ICON_RC})
    endif()
endif()

# Link directories (must be before add_executable)
if(OPENSSL_DIR)
    message(STATUS "OPENSSL_DIR = ${OPENSSL_DIR}")
    link_directories(${OPENSSL_DIR}/lib)
endif()

if(WIN32 AND VCPKG_LIB_DIR)
    message(STATUS "VCPKG_LIB_DIR = ${VCPKG_LIB_DIR}")
    message(STATUS "  include: ${VCPKG_LIB_DIR}/include")
    message(STATUS "  lib: ${VCPKG_LIB_DIR}/lib")
    link_directories(${VCPKG_LIB_DIR}/lib)
endif()

# Platform-specific executable
if(APPLE)
    add_executable(${PROJECT_NAME} MACOSX_BUNDLE ${SOURCES} ${HEADERS} ${ICON_RESOURCE})
    set_target_properties(${PROJECT_NAME} PROPERTIES
        MACOSX_BUNDLE_BUNDLE_NAME "JsNetwork"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.jsnetwork.app"
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/resources/Info.plist.in"
    )
elseif(WIN32)
    add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS})
endif()

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(OPENSSL_DIR)
    target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_DIR}/include)
endif()

if(WIN32 AND VCPKG_LIB_DIR)
    target_include_directories(${PROJECT_NAME} PRIVATE ${VCPKG_LIB_DIR}/include)
endif()

if(WIN32 AND DEFINED NPCAP_SDK_DIR AND NPCAP_SDK_DIR)
    target_include_directories(${PROJECT_NAME} PRIVATE ${NPCAP_SDK_DIR}/Include)
    target_link_directories(${PROJECT_NAME} PRIVATE ${NPCAP_SDK_DIR}/Lib)
endif()

if(APPLE AND DEFINED PCAP_DIR AND PCAP_DIR)
    target_include_directories(${PROJECT_NAME} PRIVATE ${PCAP_DIR}/include)
    target_link_directories(${PROJECT_NAME} PRIVATE ${PCAP_DIR}/lib)
endif()

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt5::Core
        Qt5::Gui
        Qt5::Widgets
        Qt5::Network
        Qt5::Sql
        libssl
        libcrypto
        ws2_32
        crypt32
        gdi32
        user32
        zlib
        wpcap
        Packet
        wininet
    )
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt5::Core
        Qt5::Gui
        Qt5::Widgets
        Qt5::Network
        Qt5::Sql
        ssl
        crypto
        z
        pcap
    )
endif()

# macOS specific
if(APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        "-framework CoreFoundation"
        "-framework Security"
    )

    # Post-build: wrap binary with launcher script for DYLD paths
    set(LAUNCHER_CONTENT
        "#!/bin/bash\n"
        "DIR=\"$(cd \"$(dirname \\\"$0\\\")\" && pwd)\"\n"
        "export DYLD_FRAMEWORK_PATH=\"${QT5_DIR}/lib\"\n"
        "export QT_PLUGIN_PATH=\"${QT5_DIR}/plugins\"\n"
        "export DYLD_LIBRARY_PATH=\"${VCPKG_LIB_DIR}/lib\"\n"
        "exec \"${CMAKE_CURRENT_BINARY_DIR}/launched\" \"\\$@\"\n"
    )
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/resources/launcher.sh.in"
        "${CMAKE_CURRENT_BINARY_DIR}/launcher_template.sh"
        @ONLY
    )
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E rename
            $<TARGET_FILE:${PROJECT_NAME}>
            $<TARGET_FILE_DIR:${PROJECT_NAME}>/${PROJECT_NAME}.bin
        COMMAND ${CMAKE_COMMAND} -E copy
            "${CMAKE_CURRENT_BINARY_DIR}/launcher_template.sh"
            $<TARGET_FILE_DIR:${PROJECT_NAME}>/${PROJECT_NAME}
        COMMAND chmod +x $<TARGET_FILE_DIR:${PROJECT_NAME}>/${PROJECT_NAME}
        COMMENT "Creating launcher wrapper for .app bundle"
    )
endif()

# Windows post-build: copy Qt DLLs and Npcap DLLs
if(WIN32)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:${PROJECT_NAME}>/platforms"
        COMMENT "Copying Qt DLLs"
    )

    # Copy Qt DLLs (standard names, found via Qt5::Core location)
    get_target_property(QT5_CORE_LOCATION Qt5::Core LOCATION)
    get_filename_component(QT5_BIN_DIR "${QT5_CORE_LOCATION}" DIRECTORY)

    foreach(QT_DLL Core Gui Widgets Network Sql)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${QT5_BIN_DIR}/Qt5${QT_DLL}.dll" "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
        )
    endforeach()

    # Qt platform plugin
    if(QT5_DIR)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${QT5_DIR}/plugins/platforms/qwindows.dll" "$<TARGET_FILE_DIR:${PROJECT_NAME}>/platforms"
        )
    endif()

    # Copy Npcap DLLs (32-bit from SysWOW64)
    if(EXISTS "C:/Windows/SysWOW64/Npcap/wpcap.dll")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "C:/Windows/SysWOW64/Npcap/wpcap.dll" "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "C:/Windows/SysWOW64/Npcap/Packet.dll" "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
            COMMENT "Copying Npcap DLLs"
        )
    endif()
endif()

# ===== Tests =====
option(BUILD_TESTS "Build unit tests" ON)

if(BUILD_TESTS)
    enable_testing()
    find_package(GTest QUIET)

    if(NOT GTest_FOUND AND VCPKG_LIB_DIR)
        find_package(GTest QUIET PATHS "${VCPKG_LIB_DIR}/share/gtest")
    endif()

    if(NOT GTest_FOUND)
        message(WARNING "GTest not found - skipping tests. Install GTest or set -DBUILD_TESTS=OFF")
        set(BUILD_TESTS OFF)
    endif()
endif()

if(BUILD_TESTS)

    set(TEST_SOURCES
        tests/test_main.cpp
        tests/test_http_parser.cpp
        tests/test_http2_parser.cpp
        tests/test_websocket_parser.cpp
        tests/test_mock_engine.cpp
        src/core/http_parser.cpp
        src/core/http2_parser.cpp
        src/core/websocket_parser.cpp
        src/core/mock_engine.cpp
        src/model/request_item.cpp
    )

    add_executable(jsnetwork_tests ${TEST_SOURCES})

    target_include_directories(jsnetwork_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    if(WIN32 AND VCPKG_LIB_DIR)
        target_include_directories(jsnetwork_tests PRIVATE ${VCPKG_LIB_DIR}/include)
    endif()

    target_link_libraries(jsnetwork_tests PRIVATE
        Qt5::Core
        Qt5::Gui
        Qt5::Widgets
        GTest::gtest
        GTest::gtest_main
    )

    if(APPLE)
        target_link_libraries(jsnetwork_tests PRIVATE z)
    elseif(WIN32)
        target_link_libraries(jsnetwork_tests PRIVATE zlib)
    endif()

    add_test(NAME JsNetworkTests COMMAND jsnetwork_tests)
endif()

# ===== Install =====
if(APPLE)
    install(TARGETS ${PROJECT_NAME} BUNDLE DESTINATION .)
elseif(WIN32)
    install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/resources/" DESTINATION bin/resources)
endif()

# ===== LSP Provider (Winsock Layered Service Provider) =====
if(WIN32)
    # LSP DLL - injected into all processes via Winsock catalog
    add_library(jsnetwork_lsp SHARED
        src/injector/lsp_provider.cpp
        src/injector/lsp_provider.h
        src/injector/jsnetwork_lsp.def
    )
    target_link_libraries(jsnetwork_lsp PRIVATE ws2_32)
    target_include_directories(jsnetwork_lsp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    set_target_properties(jsnetwork_lsp PROPERTIES
        OUTPUT_NAME "jsnetwork_lsp"
    )

    # LSP Installer/Uninstaller
    add_executable(lsp_installer
        src/injector/lsp_installer.cpp
    )
    target_link_libraries(lsp_installer PRIVATE ws2_32)
    set_target_properties(lsp_installer PROPERTIES
        OUTPUT_NAME "lsp_installer"
    )

    # Copy LSP DLL and installer to main app output directory
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:jsnetwork_lsp> "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:lsp_installer> "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
        COMMENT "Copying LSP DLL and installer to output"
    )
endif()

# ===== Packaging =====
set(CPACK_PACKAGE_NAME "JsNetwork")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION "Cross-platform HTTP/HTTPS packet capture tool")
set(CPACK_PACKAGE_VENDOR "JsNetwork")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

if(APPLE)
    set(CPACK_GENERATOR "DragNDrop")
    set(CPACK_DMG_FORMAT "UDBZ")
    set(CPACK_DMG_VOLUME_NAME "JsNetwork")
    set(CPACK_SYSTEM_NAME "macOS")
elseif(WIN32)
    set(CPACK_GENERATOR "NSIS")
    set(CPACK_NSIS_DISPLAY_NAME "JsNetwork")
    set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES")
endif()

include(CPack)
