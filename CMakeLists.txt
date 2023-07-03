cmake_minimum_required(VERSION 3.23)
project(dwm_eotf C)

set(CMAKE_C_STANDARD 99)

add_executable(dwm_eotf main.c DXBCChecksum.c admin.o)
target_link_libraries(dwm_eotf setupapi uuid)
target_link_libraries(dwm_eotf "$<$<CONFIG:Release>:-s>")
