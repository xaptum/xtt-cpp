cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
set(CMAKE_CXX_STANDARD_REQUIRED on)

project(xtt-cpp
        VERSION "0.3.0"
        )
set(XTT_CPP_VERSION ${PROJECT_VERSION})
set(XTT_CPP_SOVERSION ${PROJECT_VERSION_MAJOR})

add_compile_options(-Wall -Wextra -Wno-missing-field-initializers)
set(CMAKE_CXX_FLAGS_RELWITHSANITIZE "${CMAKE_CXX_FLAGS_RELWITHSANITIZE} -O2 -g -fsanitize=address,undefined -fsanitize=unsigned-integer-overflow")
set(CMAKE_CXX_FLAGS_DEV "${CMAKE_CXX_FLAGS_RELEASE} -Werror")
set(CMAKE_CXX_FLAGS_DEVDEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Werror")

include(GNUInstallDirs)
include(CTest)
option(BUILD_SHARED_LIBS "Build as a shared library" ON)
option(BUILD_STATIC_LIBS "Build as a static library" OFF)

# If not building as a shared library, force build as a static.  This
# is to match the CMake default semantics of using
# BUILD_SHARED_LIBS = OFF to indicate a static build.
if(NOT DEFINED BUILD_SHARED_LIBS OR NOT  "${BUILD_SHARED_LIBS}")
  set(BUILD_STATIC_LIBS ON CACHE BOOL "Build as a static library" FORCE)
endif()

find_package(Threads REQUIRED QUIET)
find_package(Boost 1.66 COMPONENTS system thread REQUIRED QUIET)

find_package(xtt 0.10.2 REQUIRED QUIET)

# In newer C++17 compilers, optional has been moved from std::experimental to std.
include(CheckIncludeFileCXX)
check_include_file_cxx("optional" HAVE_OPTIONAL)
if(HAVE_OPTIONAL)
  set(CMAKE_CXX_STANDARD 17)
  set(OPTIONAL_NS "::std")
  set(OPTIONAL_H "<optional>")
else()
  set(CMAKE_CXX_STANDARD 14)
  set(OPTIONAL_NS "::std::experimental")
  set(OPTIONAL_H "<experimental/optional>")
endif()

add_subdirectory(cpp)
add_subdirectory(asio)

################################################################################
# CMake export
################################################################################
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/xtt-cpp)

install(EXPORT xtt-cpp-targets
        FILE xtt-cpp-targets.cmake
        NAMESPACE xtt::
        DESTINATION ${INSTALL_CONFIGDIR}
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/xtt-cpp-config-version.cmake
  VERSION ${XTT_CPP_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/xtt-cpp-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/xtt-cpp-config.cmake
  INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/xtt-cpp-config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/xtt-cpp-config-version.cmake
  DESTINATION ${INSTALL_CONFIGDIR}
)


################################################################################
# Examples
################################################################################
if(BUILD_EXAMPLES)
        add_subdirectory(examples)
endif()

################################################################################
# Tests
################################################################################
add_subdirectory(test)
