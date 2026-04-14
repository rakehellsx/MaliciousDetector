cmake_minimum_required(VERSION 3.10)
project(gen_data C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 优化级别
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_C_FLAGS_RELEASE "-O2 -Wall -Wextra")

# 查找 cJSON
find_package(PkgConfig REQUIRED)
pkg_check_modules(CJSON REQUIRED libcjson)

# 查找 SQLite3
find_package(SQLite3 REQUIRED)

# 可执行文件
add_executable(gen_data gen_data.c)

target_include_directories(gen_data PRIVATE
    ${CJSON_INCLUDE_DIRS}
    ${SQLite3_INCLUDE_DIRS}
)

target_link_libraries(gen_data
    ${CJSON_LIBRARIES}
    ${SQLite3_LIBRARIES}
)

# 安装目标（可选）
install(TARGETS gen_data DESTINATION bin)
