cmake_minimum_required(VERSION 3.2)
project(social3)


add_executable(social3 main.cpp)
find_package(Crow CONFIG REQUIRED)
target_link_libraries(social3 PRIVATE Crow::Crow)
find_package(hiredis CONFIG REQUIRED)
target_link_libraries(social3 PRIVATE hiredis::hiredis)
find_package(redis++ CONFIG REQUIRED)
if(TARGET redis++::redis++_static)
    target_link_libraries(social3 PRIVATE redis++::redis++_static)
else()
    target_link_libraries(social3 PRIVATE redis++::redis++)
endif()

find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(social3 PRIVATE nlohmann_json::nlohmann_json)
file(COPY templates DESTINATION ${CMAKE_BINARY_DIR})

set(CMAKE_CXX_STANDARD 23)
