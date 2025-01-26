include_directories(..)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 ")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb -O2 -pthread")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined,address")

add_executable(socks4-client socks4-client.cpp)

add_executable(socks5-ssl-client socks5-ssl-client.cpp)
target_link_libraries(socks5-ssl-client Boost::headers ssl crypto)
