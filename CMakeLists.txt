cmake_minimum_required(VERSION 3.28)
project(celest_dns C)

set(CMAKE_C_STANDARD 17)

include(CTest)
add_subdirectory(external)
add_subdirectory(lib/src)
add_subdirectory(lib/test)
add_subdirectory(cli/src)
