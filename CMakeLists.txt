cmake_minimum_required(VERSION 3.5)
project(dns_proxy C)

set(CMAKE_C_STANDARD 11)
file(GLOB_RECURSE SOURCES main.c src/*.c)

add_executable(dns_proxy ${SOURCES})
include_directories("./include")