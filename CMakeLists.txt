cmake_minimum_required(VERSION 3.5.1)
project(pcap2PCD)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
set(CMAKE_BUILD_TYPE Release)
#set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}) 

# eigen
find_package(Eigen3 REQUIRED)
include_directories(${EIGEN3_INCLUDE_DIR})

# pcl
find_package(PCL 1.8 REQUIRED)
add_definitions(${PCL_DEFINITIONS})
include_directories(${PCL_INCLUDE_DIRS})

include_directories(include)
add_executable(pcap2PCD src/Pcap2PCD.cpp)
target_link_libraries(pcap2PCD ${PCL_LIBRARIES} -lpcap)

