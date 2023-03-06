cmake_minimum_required(VERSION 3.19)

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")

project(tunl)

if(DEFINED ENV{OS} AND "$ENV{OS}" STREQUAL "Windows_NT")
    set(OS_PLATFORM "win32")
else()
    set(OS_PLATFORM "linux")
endif()

include_directories("common")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wno-unknown-pragmas -std=c11")

set(CMAKE_C_STANDARD 11)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-unknown-pragmas -std=gnu++20 -static-libstdc++ -static-libgcc")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath,'$ORIGIN/'")

set(SOURCE_FILES main.cpp sniff.cpp reply.cpp tunnel.cpp)

SET(LIBRARY_OUTPUT_PATH "${tunl_SOURCE_DIR}/${CMAKE_BUILD_TYPE}")

SET(EXECUTABLE_OUTPUT_PATH "${LIBRARY_OUTPUT_PATH}")

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

add_library(log STATIC IMPORTED) # or STATIC instead of SHARED
set_target_properties(log PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/common/liblog.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/.."
    )

add_library(fmtd STATIC IMPORTED) # or STATIC instead of SHARED
set_target_properties(fmtd PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/common/libfmtd.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/.."
    )

target_link_libraries(${PROJECT_NAME} log fmtd popt)

set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${EXECUTABLE_OUTPUT_PATH}"
)
