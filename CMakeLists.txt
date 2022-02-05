cmake_minimum_required(VERSION 3.22)
project(pybpf_asm)

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

find_package(PythonExtensions REQUIRED)
find_package(Cython REQUIRED)

add_subdirectory(bpf_asm)
