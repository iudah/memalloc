cmake_minimum_required(VERSION 3.15)

project(memalloc VERSION 2.0.4 LANGUAGES C)

set(TARGET memalloc)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(BUILD_EXECUTABLE "Build test executable " ON)
option(ENABLE_SANITIZERS "Enable Address and Undefined Behaviours Sanitizers" OFF)

message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID}")
message(STATUS "System Processor: ${CMAKE_SYSTEM_PROCESSOR}")

add_library(${TARGET} STATIC mem.c)

target_include_directories(${TARGET}
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_compile_options(${TARGET} PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-fPIC>
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    if(MSVC)
        target_compile_options(${TARGET} PRIVATE /Zi /Od /RTC1)
        target_link_options(${TARGET} PRIVATE /DEBUG)
    else()
        target_compile_options(${TARGET} PRIVATE -g -O0 -fno-omit-frame-pointer)
    endif()
    if(ENABLE_SANITIZERS AND NOT MSVC)
        target_compile_options(${TARGET} PRIVATE -fsanitize=address -fsanitize=undefined)
        target_link_options(${TARGET} PRIVATE -fsanitize=address -fsanitize=undefined)
    endif()
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64" AND NOT MSVC)
    include(CheckCCompilerFlag)
    check_c_compiler_flag("-mfpu=neon" HAS_NEON_FLAG)
    if(HAS_NEON_FLAG)
        target_compile_options(${TARGET} PRIVATE -mfpu=neon)
    endif()
endif()

if(BUILD_EXECUTABLE)
    add_executable(${TARGET}_exe main.c)
    target_link_libraries(${TARGET}_exe PRIVATE ${TARGET})
endif()

include(GNUInstallDirs)

install(TARGETS ${TARGET}
    EXPORT MemAllocTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES mem.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT MemAllocTargets
    FILE memalloc-config.cmake
    NAMESPACE memalloc::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/memalloc)

export(EXPORT MemAllocTargets
    FILE "${CMAKE_BINARY_DIR}/memalloc-config.cmake")
