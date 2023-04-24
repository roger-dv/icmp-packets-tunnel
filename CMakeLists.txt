cmake_minimum_required(VERSION 3.19)

#set(CMAKE_C_COMPILER "gcc")
#set(CMAKE_CXX_COMPILER "g++")

project(tunl)

# set option to link the C++ std lib (for g++ or clang++)
if(DEFINED CMAKE_CXX_COMPILER)
    message(STATUS "CMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
    if(CMAKE_CXX_COMPILER MATCHES "^(.*/)?g\\+\\+$")
        set(CXX_LIB_OPTN "-static-libstdc++")
        set(CLANG_LINKER_OPTN "")
    elseif(CMAKE_CXX_COMPILER MATCHES "^(.*/)?clang\\+\\+$")
        set(CXX_LIB_OPTN "-stdlib=libstdc++")
        set(CLANG_LINKER_OPTN "-fuse-ld=lld")
    else()
        set(CXX_LIB_OPTN "")
        set(CLANG_LINKER_OPTN "")
        message(STATUS "unknown C++ compiler: CMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
    endif()
endif()
message(STATUS "CXX_LIB_OPTN=${CXX_LIB_OPTN}")

set(CPM_DOWNLOAD_VERSION 0.38.1)
set(CPM_DOWNLOAD_LOCATION "${CMAKE_BINARY_DIR}/cmake/CPM_${CPM_DOWNLOAD_VERSION}.cmake")

if(NOT (EXISTS ${CPM_DOWNLOAD_LOCATION}))
    message(STATUS "Downloading CPM.cmake")
    file(DOWNLOAD https://github.com/TheLartians/CPM.cmake/releases/download/v${CPM_DOWNLOAD_VERSION}/CPM.cmake ${CPM_DOWNLOAD_LOCATION})
endif()

include(${CPM_DOWNLOAD_LOCATION})

CPMAddPackage(
    NAME spdlog
    GITHUB_REPOSITORY gabime/spdlog
    VERSION 1.9.2)

if(DEFINED ENV{OS} AND "$ENV{OS}" STREQUAL "Windows_NT")
    set(OS_PLATFORM "win32")
else()
    set(OS_PLATFORM "linux")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wno-unknown-pragmas -std=c11")

set(CMAKE_C_STANDARD 11)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-unknown-pragmas -std=c++20 ${CXX_LIB_OPTN}")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${CLANG_LINKER_OPTN} -Wl,-rpath,'$ORIGIN/'")

set(SOURCE_FILES main.cpp sniff.cpp reply.cpp tunnel.cpp relay.cpp)

SET(LIBRARY_OUTPUT_PATH "${tunl_SOURCE_DIR}/${CMAKE_BUILD_TYPE}")

SET(EXECUTABLE_OUTPUT_PATH "${LIBRARY_OUTPUT_PATH}")

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME} cap spdlog)

set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${EXECUTABLE_OUTPUT_PATH}"
)
