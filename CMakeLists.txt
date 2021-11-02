project(asio-socks45-client)
cmake_minimum_required(VERSION 3.5)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

set(BOOST_ROOT /home/sehe/custom/boost_1_77_0)
find_package(Boost 1.70.0 REQUIRED)

add_subdirectory(examples)
