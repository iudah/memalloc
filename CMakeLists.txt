cmake_minimum_required(VERSION 3.15)

project(memalloc VERSION 2.0.1)

set(TARGET memalloc)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS     "-fPIC")


add_library(${TARGET} STATIC)
target_sources(${TARGET} PRIVATE mem.c)

option(BUILD_EXEC "build test executable " ON)
if(BUILD_EXEC)
add_executable(${TARGET}_exe main.c)
target_link_libraries(${TARGET}_exe PRIVATE ${TARGET})
endif()

install(TARGETS ${TARGET} DESTINATION lib)
install(FILES mem.h DESTINATION include)
