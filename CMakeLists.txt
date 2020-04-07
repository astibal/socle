cmake_minimum_required(VERSION 2.8)

SET(SOCLE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

include_directories ("${SOCLE_DIR}")
include_directories ("common/")

add_library(socle_lib baseproxy.hpp lrproxy.hpp baseproxy.cpp hostcx.hpp hostcx.cpp lrproxy.cpp masterproxy.hpp masterproxy.cpp basecom.hpp basecom.cpp tcpcom.hpp tcpcom.cpp udpcom.hpp udpcom.cpp sslcom.hpp sslcom.cpp sslcom_dh.cpp sslmitmcom.hpp sslmitmcom.cpp sslcertstore.hpp sslcertstore.cpp traflog.hpp apphostcx.cpp epoll.hpp epoll.cpp sobject.cpp uxcom.cpp sslcertval.cpp traflog.cpp iproxy.hpp threadedworker.hpp)
target_link_libraries(socle_lib socle_common_lib)

if(UNIX)
    IF(NOT CMAKE_BUILD_TYPE)
        SET(CMAKE_BUILD_TYPE Debug)
    ENDIF(NOT CMAKE_BUILD_TYPE)

    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-psabi -std=c++17 -g -O3")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O3")
    SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -flto -s -DBUILD_RELEASE")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
    SET(CMAKE_AR  "gcc-ar")
    SET(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
    SET(CMAKE_CXX_ARCHIVE_FINISH   true)

    # detect Alpine - and disable backtrace_* function use
    if(EXISTS "/etc/alpine-release")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLIBC_MUSL")
    endif()
endif()

if(EXISTS "${SOCLE_DIR}/.git")
    execute_process(
            COMMAND git rev-parse --abbrev-ref HEAD
            WORKING_DIRECTORY ${SOCLE_DIR}
            OUTPUT_VARIABLE SOCLE_GIT_BRANCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
            COMMAND git log -1 --format=%h
            WORKING_DIRECTORY ${SOCLE_DIR}
            OUTPUT_VARIABLE SOCLE_GIT_COMMIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
            COMMAND git describe --tags --dirty
            WORKING_DIRECTORY ${SOCLE_DIR}
            OUTPUT_VARIABLE SOCLE_GIT_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )


else(EXISTS "${SOCLE_DIR}/.git")
    set(SOCLE_GIT_BRANCH "")
    set(SOCLE_GIT_COMMIT_HASH "")
    set(SOCLE_GIT_VERSION "")
endif(EXISTS "${SOCLE_DIR}/.git")

message(STATUS "Git current socle branch: ${SOCLE_GIT_BRANCH}")
message(STATUS "Git commit socle hash: ${SOCLE_GIT_COMMIT_HASH}")
message(STATUS "Git commit socleversion: ${SOCLE_GIT_VERSION}")

message(STATUS "Generating socle_version.h")

configure_file(
        ${SOCLE_DIR}/socle_version.h.in
        ${SOCLE_DIR}/socle_version.h
)

