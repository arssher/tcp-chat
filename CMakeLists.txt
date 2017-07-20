cmake_minimum_required(VERSION 3.6)
project(tcp_chat)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -Wall -pedantic -Werror=vla")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -std=c99")

set(SOURCE_FILES server.c)
add_executable(tcp_chat ${SOURCE_FILES})