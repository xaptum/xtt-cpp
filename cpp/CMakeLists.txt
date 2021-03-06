# Copyright 2018 Xaptum, Inc.
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

configure_file("config.hpp.in" "include/xtt/config.hpp")

set(XTT_CPP_SRC_FILES
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/server_handshake_context.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/server_certificate_context.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/group_public_key_context.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/pseudonym.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/identity.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/group_identity.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/longterm_key.cpp
        )

################################################################################
# Shared Libary
################################################################################
if(BUILD_SHARED_LIBS)
        add_library(xtt-cpp ${XTT_CPP_SRC_FILES})

        set_target_properties(xtt-cpp PROPERTIES
                VERSION "${XTT_CPP_VERSION}"
                SOVERSION "${XTT_CPP_SOVERSION}"
        )

        target_include_directories(xtt-cpp
                PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
                $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(xtt-cpp
                PUBLIC
                xtt::xtt
                ${Boost_LIBRARIES}
        )

        install(TARGETS xtt-cpp
                EXPORT xtt-cpp-targets
                RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
                LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        )
endif()

################################################################################
# Static Libary
################################################################################
if(BUILD_STATIC_LIBS)
        add_library(xtt-cpp_static STATIC ${XTT_CPP_SRC_FILES})

        set_target_properties(xtt-cpp_static PROPERTIES
                OUTPUT_NAME "xtt-cpp${STATIC_SUFFIX}"
                VERSION "${XTT_CPP_VERSION}"
                SOVERSION "${XTT_CPP_SOVERSION}"
        )

        target_include_directories(xtt-cpp_static
                PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(xtt-cpp_static
                PUBLIC
                xtt::xtt_static
                ${Boost_LIBRARIES}
              )

        install(TARGETS xtt-cpp_static
                EXPORT xtt-cpp-targets
                RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
                LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        )
endif()

################################################################################
# Headers
################################################################################
install(FILES include/xtt.hpp DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(DIRECTORY include/xtt DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/xtt DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

################################################################################
# pkgconfig
################################################################################
configure_file(${PROJECT_SOURCE_DIR}/xtt-cpp.pc.in xtt-cpp.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/xtt-cpp.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
