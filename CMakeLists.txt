cmake_minimum_required(VERSION 3.23)
project(dwm_eotf C)

set(CMAKE_C_STANDARD 99)

add_executable(dwm_eotf main.c DXBCChecksum.c)
target_link_libraries(dwm_eotf setupapi uuid)
    
if(MINGW)
    target_sources(dwm_eotf PRIVATE admin.o)
    target_link_options(dwm_eotf PRIVATE "$<$<CONFIG:Release>:-s>")
else()
    set_target_properties(dwm_eotf PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")
endif()
