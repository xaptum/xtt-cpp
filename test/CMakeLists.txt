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

set(CURRENT_TEST_BINARY_DIR ${CMAKE_BINARY_DIR}/testBin/)

function(add_test_case case_file)
  get_filename_component(case_name ${case_file} NAME_WE)

  add_executable(${case_name} ${case_file})

  target_include_directories(${case_name}
    PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/cpp/src/internal>
    )

  if(BUILD_SHARED_LIBS)
    target_link_libraries(${case_name} PRIVATE
      xtt-asio
      )
  else()
    target_link_libraries(${case_name} PRIVATE
      xtt-asio_static
      )
  endif()

  set_target_properties(${case_name} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CURRENT_TEST_BINARY_DIR}
  )

  add_test(NAME ${case_name}
    COMMAND ${CURRENT_TEST_BINARY_DIR}/${case_name}
  )
endfunction()

set(XTT_CPP_TEST_FILES
  internal-text_to_binary_Test.cpp
  group_identity_Test.cpp
  group_public_key_context_Test.cpp
  identity_Test.cpp
  longterm_key_Test.cpp
  pseudonym_Test.cpp
  server_certificate_Test.cpp
  )

foreach(test_file ${XTT_CPP_TEST_FILES})
  add_test_case(${test_file})
endforeach()
