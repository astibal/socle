cmake_minimum_required(VERSION 2.8)

include_directories ("${PROJECT_SOURCE_DIR}")
include_directories ("common/")

add_library(socle_lib baseproxy.hpp lrproxy.hpp baseproxy.cpp hostcx.hpp hostcx.cpp lrproxy.cpp threadedproxy.hpp threadedproxy.impl masterproxy.hpp masterproxy.cpp basecom.hpp basecom.cpp sslcom.cpp sslcom.hpp sslmitmcom.hpp sslmitmcom.cpp sslcertstore.hpp sslcertstore.cpp traflog.hpp apphostcx.hpp)

if(UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")
endif()

