cmake_minimum_required(VERSION 3.21)

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_BUILD_TYPE Debug)
# set (CMAKE_BUILD_TYPE Release)
project(WebviewTK)

# BUILD DEMO EXECUTABLE #
#link_directories("./build")

add_executable(browser ./examples/Browser/browser.cpp)

if (UNIX)
	if(APPLE)
		target_link_libraries(browser PUBLIC "-framework WebKit")
	else()
		message("Linux build not supported yet")
	endif(APPLE)
endif (UNIX)

if (WIN32)

#target_link_options(app PRIVATE -mwindows)
endif (WIN32)

