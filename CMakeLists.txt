cmake_minimum_required(VERSION 3.30)
project(asio-socks45-client)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

find_package(Boost CONFIG 1.77.0 REQUIRED)

add_definitions(-DBOOST_ASIO_NO_DEPRECATED=1)
add_subdirectory(examples)
