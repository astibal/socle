add_library(socle_common_lib timeops.hpp timeops.cpp logger.hpp logger.cpp display.hpp display.cpp buffer.hpp crc32.hpp crc32.cpp ranges.cpp ltventry.cpp buffer.cpp ptr_cache.hpp)

if(UNIX)
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")
endif()


