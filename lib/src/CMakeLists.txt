add_library(compass_lib STATIC compass_dns.h compass_dns.c)
target_include_directories(compass_lib PUBLIC ${CMAKE_CURRENT_LIST_DIR})