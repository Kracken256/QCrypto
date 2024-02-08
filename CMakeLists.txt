cmake_minimum_required(VERSION 3.15)
project(libqcrypto CXX C)

file(GLOB_RECURSE SOURCES "src/*.c")

# Set C standard
set(CMAKE_C_STANDARD 11)

add_library(qcrypto SHARED ${SOURCES})
target_compile_options(qcrypto PRIVATE -O3 -fPIC -Wall -Wextra -pedantic -Werror -fvisibility=hidden -g -flto)
target_include_directories(qcrypto PUBLIC include)

add_library(qcrypto-static STATIC ${SOURCES})
target_compile_options(qcrypto-static PRIVATE -O3 -fPIC -Wall -Wextra -Werror -pedantic -fvisibility=hidden -g -flto)
target_include_directories(qcrypto-static PUBLIC include)

set_target_properties(qcrypto-static PROPERTIES OUTPUT_NAME qcrypto)

# Install the library
install(TARGETS qcrypto
        LIBRARY DESTINATION /usr/lib
        ARCHIVE DESTINATION /usr/lib
        PUBLIC_HEADER DESTINATION /usr/include/qcrypto)

# Built tests tests/*.cpp
file(GLOB_RECURSE TEST_SOURCES "tests/*.c")
foreach(TEST_SOURCE ${TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
    add_executable(test-${TEST_NAME} ${TEST_SOURCE})
    target_compile_options(test-${TEST_NAME} PRIVATE -O3 -Wall -Wextra -pedantic -g -flto)
    target_link_libraries(test-${TEST_NAME} qcrypto crypto)
    target_include_directories(test-${TEST_NAME} PUBLIC include)
endforeach()
