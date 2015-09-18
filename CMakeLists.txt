cmake_minimum_required(VERSION 3.3)
project(rtp_analyzer)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -lpcap")

set(SOURCE_FILES main.cpp)
add_executable(rtp_analyzer ${SOURCE_FILES})