cmake_minimum_required(VERSION 2.8)

project(pcapcli)
add_executable(${PROJECT_NAME} "main.c")
target_link_libraries(pcapcli pcap)
