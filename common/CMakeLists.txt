cmake_minimum_required(VERSION 3.0)

project(socle-common CXX)

include_directories ("${PROJECT_SOURCE_DIR}")

add_library(
		socle_common_lib
		timeops.hpp
		timeops.cpp
		display.hpp
		display.cpp
		buffer.hpp
		crc32.hpp
		crc32.cpp
		ranges.cpp
		ltventry.cpp
		buffer.cpp
		ptr_cache.hpp
		internet.cpp
		lockable.hpp
		lockbuffer.hpp
		biostring.cpp
		stringformat.hpp
		log/logger.hpp
		log/logger.cpp
		log/loggermac.hpp
		log/loglevel.hpp
		log/loglevel.cpp
		log/logan.hpp
		log/logan.cpp
		mempool/mempool.cpp
		mempool/mpallocator.hpp
		mempool/mperror.hpp
		mempool/canary.hpp
		mpstd.hpp
		mpdisplay.hpp
		mpdisplay.cpp
        biomem.hpp
		socle_size.hpp
		epoll.cpp
		xorshift.hpp
		numops.hpp)

if(UNIX)
	IF(NOT CMAKE_BUILD_TYPE)
		SET(CMAKE_BUILD_TYPE Debug)
	ENDIF(NOT CMAKE_BUILD_TYPE)


	# Pedantic complains about designated initializers (C++20)
	# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Wno-unused-parameter -Wno-psabi -std=c++17")
	# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wno-unused-parameter -Werror -Wno-unused-function -Wconversion -Wno-psabi -std=c++17")
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wno-unused-variable -Wno-unused-parameter -Wno-unused-function -Wno-psabi -std=c++17")
	SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -fno-stack-protector")

	if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-stringop-truncation ")
		if("${OPT_GCC_UNROLL}" STREQUAL "Y")
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-stringop-truncation -funroll-loops --param  max-unrolled-insns=4")
		endif()
	elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-string-concatenation  -Wno-overloaded-virtual -Wno-unused-command-line-argument")
	endif()

	IF (CMAKE_BUILD_TYPE STREQUAL "Coverity")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG}")
	ENDIF()

	IF (CMAKE_BUILD_TYPE STREQUAL "Debug")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG}")

		if("${OPT_DEBUG_ASAN_THREADS}" STREQUAL "Y")
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fPIE -pie")
		endif()
		if("${OPT_DEBUG_ASAN_LEAKS}" STREQUAL "Y")
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=leak -fPIE -pie")
		endif()
		if("${OPT_DEBUG_ASAN_UB}" STREQUAL "Y")
			add_definitions(-DASAN_UB)
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined  -fPIE -pie")
		endif()
	ENDIF()

	IF (CMAKE_BUILD_TYPE STREQUAL "Release")
		message(">>> release: enabling optimizations (socle/common)")
		SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fstack-protector-strong -O3 -flto -s -DBUILD_RELEASE")
		SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
	ENDIF()

	SET(CMAKE_AR  "gcc-ar")
	SET(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
	SET(CMAKE_CXX_ARCHIVE_FINISH   true)

	# detect Alpine - and disable backtrace_* function use
	if(EXISTS "/etc/alpine-release")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLIBC_MUSL")
	endif()
endif()


