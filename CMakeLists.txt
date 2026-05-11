cmake_minimum_required(VERSION 3.14)
project(JsNetwork VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Qt5 path from vcpkg
set(QT5_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../code/debug/xwares/vcpkg_install_arm64/qt5/build_arm64/qtbase")
set(CMAKE_PREFIX_PATH "${QT5_DIR}")

find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets Network Sql)

# Third-party paths
set(OPENSSL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../code/debug/xwares/vcpkg_install_arm64/default/arm64-osx-dynamic")
set(VCPKG_LIB_DIR "${OPENSSL_DIR}")

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

add_executable(${PROJECT_NAME} MACOSX_BUNDLE ${SOURCES} ${HEADERS} ${ICON_RESOURCE})

set_target_properties(${PROJECT_NAME} PROPERTIES
    MACOSX_BUNDLE_BUNDLE_NAME "JsNetwork"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.jsnetwork.app"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/resources/Info.plist.in"
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${QT5_DIR}/include
    ${VCPKG_LIB_DIR}/include
)

target_link_directories(${PROJECT_NAME} PRIVATE
    ${VCPKG_LIB_DIR}/lib
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    Qt5::Network
    Qt5::Sql
    ssl
    crypto
    z
)

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

# ===== Tests =====
option(BUILD_TESTS "Build unit tests" ON)

if(BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED PATHS "${VCPKG_LIB_DIR}/share/gtest")

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
        ${QT5_DIR}/include
        ${VCPKG_LIB_DIR}/include
    )

    target_link_directories(jsnetwork_tests PRIVATE
        ${VCPKG_LIB_DIR}/lib
    )

    target_link_libraries(jsnetwork_tests PRIVATE
        Qt5::Core
        Qt5::Gui
        Qt5::Widgets
        GTest::gtest
        GTest::gtest_main
        z
    )

    add_test(NAME JsNetworkTests COMMAND jsnetwork_tests)
endif()

# ===== Install =====
if(APPLE)
    install(TARGETS ${PROJECT_NAME} BUNDLE DESTINATION .)
elseif(WIN32)
    install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
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
