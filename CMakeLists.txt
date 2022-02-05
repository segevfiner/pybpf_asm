cmake_minimum_required(VERSION 3.22)
project(pybpf_asm)

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

if(WIN32)
    set(FLEX_COMPILE_FLAGS "--wincompat")
endif()

flex_target(bpf_exp bpf_exp.l bpf_exp.flex.c COMPILE_FLAGS "${FLEX_COMPILE_FLAGS}" DEFINES_FILE bpf_exp.flex.h)
bison_target(bpf_exp bpf_exp.y bpf_exp.yacc.c)
add_flex_bison_dependency(bpf_exp bpf_exp)

add_library(bpf_asm MODULE ${FLEX_bpf_exp_OUTPUTS} ${BISON_bpf_exp_OUTPUTS})
target_include_directories(bpf_asm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(bpf_asm PUBLIC c_std_11)
