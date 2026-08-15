cmake_minimum_required(VERSION 4.2)
project(BinPatch)
include(CheckIPOSupported)

set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

check_ipo_supported(RESULT ipo_supported)
if(ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

if(MSVC)
	add_compile_options(
        $<$<CONFIG:Release>:/Gw>
        $<$<CONFIG:Release>:/MP>
	)
endif()

set(LIEF_PYTHON_API OFF CACHE BOOL "" FORCE)
set(LIEF_C_API OFF CACHE BOOL "" FORCE)
set(LIEF_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LIEF_TESTS OFF CACHE BOOL "" FORCE)

set(LIEF_ART OFF CACHE BOOL "" FORCE)
set(LIEF_DEX OFF CACHE BOOL "" FORCE)
set(LIEF_ELF OFF CACHE BOOL "" FORCE)
set(LIEF_MACHO OFF CACHE BOOL "" FORCE)
set(LIEF_OAT OFF CACHE BOOL "" FORCE)
set(LIEF_ENABLE_JSON OFF CACHE BOOL "" FORCE)
set(LIEF_DISABLE_FROZEN ON CACHE BOOL "" FORCE)
set(LIEF_OPT_MBEDTLS_ENABLED OFF CACHE BOOL "" FORCE)
add_subdirectory(thirdparty/LIEF SYSTEM)

set(BUILD_LIBS_ONLY ON CACHE BOOL "" FORCE)
set(KEYSTONE_BUILD_STATIC_RUNTIME OFF CACHE BOOL "" FORCE)
set(LLVM_TARGETS_TO_BUILD X86 CACHE STRING "" FORCE)
set(LLVM_ENABLE_BACKTRACES OFF CACHE BOOL "" FORCE)
set(LLVM_BUILD_RUNTIME OFF CACHE BOOL "" FORCE)
add_subdirectory(thirdparty/keystone SYSTEM)

set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
add_subdirectory(thirdparty/yaml-cpp SYSTEM)

set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
add_subdirectory(thirdparty/zydis SYSTEM)

add_executable(BinPatch 
    main.cpp
    pattern_utils.h
    pattern_utils.cpp
    assembler.h
    assembler.cpp
    dissasembler.h
    dissasembler.cpp
)

target_compile_options(${PROJECT_NAME} PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Werror>
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    LIEF::LIEF
    keystone
    yaml-cpp
	Zydis::Zydis    
)