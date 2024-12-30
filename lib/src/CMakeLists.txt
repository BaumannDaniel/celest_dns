add_library(celest_lib STATIC celest_dns.h celest_dns.c)
target_include_directories(celest_lib PUBLIC ${CMAKE_CURRENT_LIST_DIR})