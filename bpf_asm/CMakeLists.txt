if(WIN32)
    set(FLEX_COMPILE_FLAGS "--wincompat")
endif()

flex_target(bpf_exp bpf_exp.l bpf_exp.flex.c COMPILE_FLAGS "${FLEX_COMPILE_FLAGS}" DEFINES_FILE bpf_exp.flex.h)
bison_target(bpf_exp bpf_exp.y bpf_exp.yacc.c)

add_cython_target(_bpf_asm)

add_library(_bpf_asm MODULE ${_bpf_asm} ${FLEX_bpf_exp_OUTPUTS} ${BISON_bpf_exp_OUTPUTS})
python_extension_module(_bpf_asm)
target_include_directories(_bpf_asm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(_bpf_asm PUBLIC c_std_11)
install(TARGETS _bpf_asm LIBRARY DESTINATION bpf_asm)
