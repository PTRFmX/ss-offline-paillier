cmake_minimum_required (VERSION 3.0)
project (ss-paillier-offline)
#set(CMAKE_BUILD_TYPE DEBUG)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -g -O0 -lgmp")

set(NAME "ss-paillier-offline")

find_package(GMP REQUIRED)

add_executable(run_offline
    src/main.cpp
    src/offline/arithmetic.cpp
    src/crypto/paillier.cpp
)

target_link_libraries(run_offline gmp)