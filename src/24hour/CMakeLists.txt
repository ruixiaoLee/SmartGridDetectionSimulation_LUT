# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALExamples VERSION 3.2.0 LANGUAGES CXX)
project(MyOpenMPProject)

# Executable will be in bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(SEAL_USE_CXX17 OFF)

add_executable(makeEnctab_1 makeEnctab_1.cpp)
# add_executable(makeEnctab_2 makeEnctab_2.cpp)
# add_executable(makeEnctab_3 makeEnctab_3.cpp)

add_executable(keyGen keyGen.cpp)
add_executable(step1_CS1 step1_CS1.cpp)
add_executable(step2_TA1 step2_TA1.cpp)
add_executable(step3_CS2 step3_CS2.cpp)
add_executable(step4_TA2 step4_TA2.cpp)
add_executable(step5_CS3 step5_CS3.cpp)
add_executable(step6_TA3 step6_TA3.cpp)
add_executable(step7_CS4 step7_CS4.cpp)
add_executable(checkRes checkRes.cpp)

# Import Microsoft SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Import OpenMP
find_package(OpenMP REQUIRED)
if(OpenMP_FOUND)
 set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
 set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

# Link Microsoft SEAL

target_link_libraries(makeEnctab_1 SEAL::seal)
# target_link_libraries(makeEnctab_2 SEAL::seal)
# target_link_libraries(makeEnctab_3 SEAL::seal)

target_link_libraries(keyGen SEAL::seal)
target_link_libraries(step1_CS1 SEAL::seal)
target_link_libraries(step2_TA1 SEAL::seal)
target_link_libraries(step3_CS2 SEAL::seal)
target_link_libraries(step4_TA2 SEAL::seal)
target_link_libraries(step5_CS3 SEAL::seal)
target_link_libraries(step6_TA3 SEAL::seal)
target_link_libraries(step7_CS4 SEAL::seal)
target_link_libraries(checkRes SEAL::seal)
