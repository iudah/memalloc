cmake_minimum_required(VERSION 3.15)

project(memalloc VERSION 2.0.2)

set(TARGET memalloc)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "-fPIC")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb3 -O0 -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined -static-libsan -mfpu=neon")


add_library(${TARGET} STATIC)
target_sources(${TARGET} PRIVATE mem.c)

option(BUILD_EXEC "build test executable " ON)
if(BUILD_EXEC)
    add_executable(${TARGET}_exe main.c)
    target_link_libraries(${TARGET}_exe PRIVATE ${TARGET})
endif()

install(TARGETS ${TARGET} EXPORT MemAllocTargets LIBRARY DESTINATION lib INCLUDES DESTINATION include)
install(FILES mem.h DESTINATION include)
install(EXPORT MemAllocTargets FILE memalloc-config.cmake DESTINATION lib/cmake/memalloc)
export(EXPORT MemAllocTargets FILE "${CMAKE_BINARY_DIR}/memalloc-config.cmake")
