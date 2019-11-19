include_directories ("${PROJECT_SOURCE_DIR}")

add_library(socle_common_lib timeops.hpp timeops.cpp logger.hpp logger.cpp display.hpp display.cpp buffer.hpp crc32.hpp crc32.cpp ranges.cpp ltventry.cpp buffer.cpp ptr_cache.hpp internet.cpp lockable.hpp lockbuffer.hpp biostring.cpp mempool.cpp stringformat.hpp)

if(UNIX)
	IF(NOT CMAKE_BUILD_TYPE)
		SET(CMAKE_BUILD_TYPE Debug)
	ENDIF(NOT CMAKE_BUILD_TYPE)


	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++17 -g")
	SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
	SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -s")
	# detect Alpine - and disable backtrace_* function use
	if(EXISTS "/etc/alpine-release")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLIBC_MUSL")
	endif()
endif()


