include_directories(..)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -Wextra ")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb -O2 -pthread")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined,address")

# specific versions of GCC appear to give a fasle positive on this warning
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-mismatched-new-delete ")

link_libraries (Boost::headers ssl crypto)

add_executable (socks4-client          socks4-client.cpp)
add_executable (socks5-ssl-client      socks5-ssl-client.cpp)
add_executable (socks5-ssl-client-coro socks5-ssl-client-coro.cpp)
add_executable (socks4-client-coro     socks4-client-coro.cpp)

target_compile_definitions(socks5-ssl-client-coro PRIVATE BOOST_ASIO_HAS_CO_AWAIT)
target_compile_definitions(socks4-client-coro     PRIVATE BOOST_ASIO_HAS_CO_AWAIT)
