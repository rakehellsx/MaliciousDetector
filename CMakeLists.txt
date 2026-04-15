cmake_minimum_required(VERSION 3.16)
project(MalwareDetector VERSION 1.0.0 LANGUAGES CXX)

# ─────────────────────────────────────────────
# C++ 标准
# ─────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ─────────────────────────────────────────────
# 编译器专用选项
# ─────────────────────────────────────────────
if(MSVC)
    # /utf-8      : 源文件和执行字符集均使用 UTF-8，解决中文注释 C4819 警告
    # /MP         : 并行编译（多核加速）
    # /W3         : 警告级别 3
    # /wd4819     : 抑制 C4819（代码页字符警告，已由 /utf-8 解决）
    # /wd4251     : 抑制 DLL 接口导出警告（Qt 内部常见）
    # /EHsc       : 标准 C++ 异常处理
    # /DNOMINMAX  : 禁用 Windows.h 中的 min/max 宏，避免与 std::min/max 冲突
    add_compile_options(
        /utf-8
        /MP
        /W3
        /wd4819
        /wd4251
        /EHsc
    )
    add_compile_definitions(
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
        UNICODE
        _UNICODE
    )
else()
    # GCC / Clang
    add_compile_options(
        -Wall
        -Wextra
        -Wno-unused-parameter
    )
endif()

# ─────────────────────────────────────────────
# Qt5 自动化工具（MOC / UIC / RCC）
# ─────────────────────────────────────────────
set(CMAKE_AUTOMOC ON)   # 自动处理 Q_OBJECT 宏
set(CMAKE_AUTOUIC ON)   # 自动处理 .ui 文件（调用 uic）
set(CMAKE_AUTORCC ON)   # 自动处理 .qrc 资源文件

# 告知 AUTOUIC 在哪里查找 .ui 文件
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_SOURCE_DIR}/ui)

# ─────────────────────────────────────────────
# 查找 Qt5 组件
# ─────────────────────────────────────────────
find_package(Qt5 REQUIRED COMPONENTS
    Core
    Gui
    Widgets
    Sql
    PrintSupport
)

# ─────────────────────────────────────────────
# 源文件列表
# ─────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/LoginDialog.cpp
    src/DatabaseManager.cpp
    src/BasicLibLoader.cpp
    src/pages/DashboardPage.cpp
    src/pages/SystemInfoPage.cpp
    src/pages/NetworkInfoPage.cpp
    src/pages/DiskInfoPage.cpp
    src/pages/ProcessInfoPage.cpp
    src/pages/PortInfoPage.cpp
    src/pages/AutorunPage.cpp
    src/pages/ScheduledTaskPage.cpp
    src/pages/DriverInfoPage.cpp
    src/pages/SharedResourcePage.cpp
    src/pages/BrowserPluginPage.cpp
    src/pages/MemoryImagePage.cpp
    src/pages/StaticScanPage.cpp
    src/pages/DynamicScanPage.cpp
    src/pages/FileAssocPage.cpp
    src/pages/SampleExtractPage.cpp
    src/pages/ReportPage.cpp
    src/pages/LogAuditPage.cpp
    src/pages/SystemSettingsPage.cpp
    src/pages/CertScanPage.cpp
)

set(HEADERS
    include/pages/BasePage.h
    include/MainWindow.h
    include/LoginDialog.h
    include/DatabaseManager.h
    include/BasicLibLoader.h
    include/IconHelper.h
    include/StyleManager.h
    include/pages/DashboardPage.h
    include/pages/SystemInfoPage.h
    include/pages/NetworkInfoPage.h
    include/pages/DiskInfoPage.h
    include/pages/ProcessInfoPage.h
    include/pages/PortInfoPage.h
    include/pages/AutorunPage.h
    include/pages/ScheduledTaskPage.h
    include/pages/DriverInfoPage.h
    include/pages/SharedResourcePage.h
    include/pages/BrowserPluginPage.h
    include/pages/MemoryImagePage.h
    include/pages/StaticScanPage.h
    include/pages/DynamicScanPage.h
    include/pages/FileAssocPage.h
    include/pages/SampleExtractPage.h
    include/pages/ReportPage.h
    include/pages/LogAuditPage.h
    include/pages/SystemSettingsPage.h
    include/pages/CertScanPage.h
    third_party/basic/basic.h
)

# .ui 文件列表（CMAKE_AUTOUIC 会自动调用 uic 生成 ui_xxx.h）
set(UI_FILES
    ui/MainWindow.ui
    ui/DashboardPage.ui
    ui/SystemInfoPage.ui
    ui/NetworkInfoPage.ui
    ui/DiskInfoPage.ui
    ui/ProcessInfoPage.ui
    ui/PortInfoPage.ui
    ui/AutorunPage.ui
    ui/ScheduledTaskPage.ui
    ui/DriverInfoPage.ui
    ui/SharedResourcePage.ui
    ui/BrowserPluginPage.ui
    ui/MemoryImagePage.ui
    ui/StaticScanPage.ui
    ui/DynamicScanPage.ui
    ui/FileAssocPage.ui
    ui/SampleExtractPage.ui
    ui/ReportPage.ui
    ui/LogAuditPage.ui
    ui/SystemSettingsPage.ui
    ui/CertScanPage.ui
    ui/LoginDialog.ui
)

# ─────────────────────────────────────────────
# Windows 平台：图标资源文件
# ─────────────────────────────────────────────
if(WIN32)
    if(EXISTS "${CMAKE_SOURCE_DIR}/resources/app.ico")
        set(WINDOWS_RC "${CMAKE_SOURCE_DIR}/resources/app.rc")
        if(NOT EXISTS "${WINDOWS_RC}")
            file(WRITE "${WINDOWS_RC}"
                "IDI_ICON1 ICON DISCARDABLE \"resources/app.ico\"\n"
            )
        endif()
        list(APPEND SOURCES ${WINDOWS_RC})
    endif()
endif()

# ─────────────────────────────────────────────
# 可执行目标
# ─────────────────────────────────────────────
if(WIN32)
    add_executable(${PROJECT_NAME} WIN32
        ${SOURCES}
        ${HEADERS}
        ${UI_FILES}
    )
else()
    add_executable(${PROJECT_NAME}
        ${SOURCES}
        ${HEADERS}
        ${UI_FILES}
    )
endif()

# ─────────────────────────────────────────────
# 头文件搜索路径
# ─────────────────────────────────────────────
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/pages
    ${CMAKE_SOURCE_DIR}/third_party/basic
    # CMAKE_AUTOUIC 生成的 ui_xxx.h 在构建目录中，CMake 自动添加
)

# ─────────────────────────────────────────────
# 链接 Qt5 库
# ─────────────────────────────────────────────
target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    Qt5::Sql
    Qt5::PrintSupport
)

# ─────────────────────────────────────────────
# 编译定义
# ─────────────────────────────────────────────
target_compile_definitions(${PROJECT_NAME} PRIVATE
    QT_DEPRECATED_WARNINGS
)

# ─────────────────────────────────────────────
# Windows 平台：链接 basic.dll 导入库（如有）
# ─────────────────────────────────────────────
if(WIN32)
    if(EXISTS "${CMAKE_SOURCE_DIR}/third_party/basic/basic.lib")
        target_link_libraries(${PROJECT_NAME} PRIVATE
            ${CMAKE_SOURCE_DIR}/third_party/basic/basic.lib
        )
    elseif(EXISTS "${CMAKE_SOURCE_DIR}/third_party/basic/libbasic.a")
        target_link_libraries(${PROJECT_NAME} PRIVATE
            ${CMAKE_SOURCE_DIR}/third_party/basic/libbasic.a
        )
    endif()
endif()

# ─────────────────────────────────────────────
# 样式文件复制到构建目录
# ─────────────────────────────────────────────
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/resources/styles
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/styles
    COMMENT "Copying QSS style files to build directory"
)

# ─────────────────────────────────────────────
# 安装规则
# ─────────────────────────────────────────────
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

# ─────────────────────────────────────────────
# 打印构建信息
# ─────────────────────────────────────────────
message(STATUS "Project:   ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "Qt5 dir:   ${Qt5_DIR}")
message(STATUS "Build dir: ${CMAKE_BINARY_DIR}")
message(STATUS "Platform:  ${CMAKE_SYSTEM_NAME}")

# ─────────────────────────────────────────────
# 测试目标（cmake -DBUILD_TEST=ON 启用）
# ─────────────────────────────────────────────
option(BUILD_TEST "Build page test executable" OFF)
if(BUILD_TEST)
    set(TEST_SOURCES
        ${CMAKE_SOURCE_DIR}/test_pages.cpp
        src/MainWindow.cpp
        src/LoginDialog.cpp
        src/DatabaseManager.cpp
        src/BasicLibLoader.cpp
        src/pages/DashboardPage.cpp
        src/pages/SystemInfoPage.cpp
        src/pages/NetworkInfoPage.cpp
        src/pages/DiskInfoPage.cpp
        src/pages/ProcessInfoPage.cpp
        src/pages/PortInfoPage.cpp
        src/pages/AutorunPage.cpp
        src/pages/ScheduledTaskPage.cpp
        src/pages/DriverInfoPage.cpp
        src/pages/SharedResourcePage.cpp
        src/pages/BrowserPluginPage.cpp
        src/pages/MemoryImagePage.cpp
        src/pages/StaticScanPage.cpp
        src/pages/DynamicScanPage.cpp
        src/pages/FileAssocPage.cpp
        src/pages/SampleExtractPage.cpp
        src/pages/ReportPage.cpp
        src/pages/LogAuditPage.cpp
        src/pages/SystemSettingsPage.cpp
        src/pages/CertScanPage.cpp
    )
    add_executable(test_pages ${TEST_SOURCES} ${HEADERS} ${UI_FILES})
    target_include_directories(test_pages PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/pages
        ${CMAKE_SOURCE_DIR}/third_party/basic
    )
    target_link_libraries(test_pages PRIVATE
        Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Sql Qt5::PrintSupport
    )
    target_compile_definitions(test_pages PRIVATE QT_DEPRECATED_WARNINGS)
    message(STATUS "Test target: test_pages")
endif()
