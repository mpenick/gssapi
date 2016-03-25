cmake_minimum_required(VERSION 2.6.4)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules/")

set(PROJECT_PROJECT_NAME gssapi)
set(PROJECT_C_FLAGS "-g")

add_executable(${PROJECT_PROJECT_NAME} gssapi.c)

find_package(Cassandra REQUIRED)
include_directories(${CASSANDRA_INCLUDE_DIRS})
target_link_libraries(${PROJECT_PROJECT_NAME} ${CASSANDRA_LIBRARIES})

find_package(Libuv REQUIRED)
include_directories(${LIBUV_INCLUDE_DIRS})
target_link_libraries(${PROJECT_PROJECT_NAME} ${LIBUV_LIBRARIES})

find_package(Kerberos REQUIRED)
include_directories(${LIBKRB5_INCLUDE_DIR})
target_link_libraries(${PROJECT_PROJECT_NAME} ${LIBKRB5_LIBRARY})

if (APPLE)
  set(PROJECT_C_FLAGS "${PROJECT_C_FLAGS} -Wno-deprecated-declarations")
endif()

set_property(
  TARGET ${PROJECT_PROJECT_NAME}
  APPEND PROPERTY COMPILE_FLAGS ${PROJECT_C_FLAGS})
