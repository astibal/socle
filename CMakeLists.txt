cmake_minimum_required(VERSION 2.8)

include_directories ("${PROJECT_SOURCE_DIR}")
include_directories ("common/")

add_library(socle_lib baseproxy.hpp lrproxy.hpp baseproxy.cpp hostcx.hpp hostcx.cpp lrproxy.cpp masterproxy.hpp masterproxy.cpp basecom.hpp basecom.cpp tcpcom.hpp tcpcom.cpp udpcom.hpp udpcom.cpp sslcom.hpp sslcom.cpp sslcom_dh.cpp sslmitmcom.hpp sslmitmcom.cpp sslcertstore.hpp sslcertstore.cpp traflog.hpp apphostcx.cpp epoll.hpp epoll.cpp sobject.cpp uxcom.cpp sslcertval.cpp traflog.cpp)
target_link_libraries(socle_lib socle_common_lib)

if(UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -std=c++17")

    # detect Alpine - and disable backtrace_* function use
    if(EXISTS "/etc/alpine-release")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLIBC_MUSL")
    endif()
endif()

