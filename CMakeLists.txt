# pybpf_asm - Python BPF Assembler
# Copyright (C) 2026  Segev Finer
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

cmake_minimum_required(VERSION 3.22...4.4)
project(${SKBUILD_PROJECT_NAME} LANGUAGES C)

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

find_package(
  Python
  COMPONENTS Interpreter Development.Module
  REQUIRED)
find_package(Cython MODULE REQUIRED VERSION 3.0)
include(UseCython)

if(WIN32)
    set(FLEX_COMPILE_FLAGS "--wincompat")
endif()

flex_target(bpf_exp bpf_asm/bpf_exp.l bpf_asm/bpf_exp.flex.c COMPILE_FLAGS "${FLEX_COMPILE_FLAGS}" DEFINES_FILE bpf_asm/bpf_exp.flex.h)
bison_target(bpf_exp bpf_asm/bpf_exp.y bpf_asm/bpf_exp.yacc.c)

cython_transpile(bpf_asm/_bpf_asm.pyx LANGUAGE C
                 OUTPUT_VARIABLE _bpf_asm_c)

python_add_library(_bpf_asm MODULE ${_bpf_asm_c} ${FLEX_bpf_exp_OUTPUTS} ${BISON_bpf_exp_OUTPUTS} WITH_SOABI)
target_include_directories(_bpf_asm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/bpf_asm ${CMAKE_CURRENT_BINARY_DIR}/bpf_asm)
target_compile_features(_bpf_asm PUBLIC c_std_11)
install(TARGETS _bpf_asm LIBRARY DESTINATION bpf_asm)
