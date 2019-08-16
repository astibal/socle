include_directories ("${PROJECT_SOURCE_DIR}")

add_library(socle_common_lib timeops.hpp timeops.cpp logger.hpp logger.cpp display.hpp display.cpp buffer.hpp crc32.hpp crc32.cpp ranges.cpp ltventry.cpp buffer.cpp ptr_cache.hpp internet.cpp lockable.hpp lockbuffer.hpp biostring.cpp mempool.cpp)

if(UNIX)
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++17")

	# detect Alpine - and disable backtrace_* function use
	if(EXISTS "/etc/alpine-release")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLIBC_MUSL")
	endif()
endif()


