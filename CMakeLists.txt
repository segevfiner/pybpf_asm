# pybpf_asm - Python BPF Assembler
# Copyright (C) 2022  Segev Finer
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

cmake_minimum_required(VERSION 3.22)
project(pybpf_asm)

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

find_package(PythonExtensions REQUIRED)
find_package(Cython REQUIRED)

add_subdirectory(bpf_asm)
