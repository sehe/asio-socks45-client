project(asio-socks45-client)
cmake_minimum_required(VERSION 3.5)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

find_package(Boost 1.70.0 REQUIRED)

add_subdirectory(examples)
