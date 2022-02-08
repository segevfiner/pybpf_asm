# pybpf_asm - Python BPF Assembler
# Copyright (C) 2022  Segev Finer
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
# cython: language_level=3str, binding=True
"""
Python BPF Assembler.

Based on the BPF assembler in Linux sources.
"""

import enum
from typing import List, Tuple
from libc.stdlib cimport free
from libc.stdint cimport uint8_t, uint16_t, uint32_t


class Error(Exception):
    """Raised when there is an error assembling BPF."""
    pass


class BpfDumpType(enum.Enum):
    DEFAULT = 0
    MULTILINE = 1
    C_ARRAY = 2


cdef extern from "bpf_exp.yacc.h" nogil:
    struct sock_filter:
        uint16_t	code   # Actual filter code
        uint8_t	    jt	   # Jump true
        uint8_t	    jf	   # Jump false
        uint32_t	k      # Generic multiuse field

    int bpf_asm_compile(const char *str, int len, sock_filter (**out), const char **error)


def assemble(str: str) -> List[Tuple[int, int, int, int]]:
    """Assemble BPF *str*."""
    cdef sock_filter *out = NULL
    cdef char *error = NULL

    strbytes = str.encode()
    strbytes_ptr = <const char*>strbytes
    strbytes_len = len(strbytes)
    with nogil:
        result = bpf_asm_compile(strbytes_ptr, strbytes_len, &out, &error)
    try:
        if not result:
            raise Error(error.decode())

        insns = []
        for insn in out[:result]:
            insns.append((insn.code, insn.jt, insn.jf, insn.k))
        return insns
    finally:
        free(out)
        free(error)


def dumps(bpf: List[Tuple[int, int, int, int]], format=BpfDumpType.DEFAULT) -> str:
    """Dump *bpf* to a str in *format*."""
    result = []

    if format == BpfDumpType.DEFAULT:
        result.append(f"{len(bpf)},")

        for insn in bpf[:-1]:
            result.append(f"{insn[0]} {insn[1]} {insn[2]} {insn[3]},")

        insn = bpf[-1]
        result.append(f"{insn[0]} {insn[1]} {insn[2]} {insn[3]}")

        return ''.join(result)

    elif format == BpfDumpType.MULTILINE:
        result.append(f"{len(bpf)}")
        for insn in bpf:
            result.append(f"{insn[0]} {insn[1]} {insn[2]} {insn[3]}")
        return '\n'.join(result)

    elif format == BpfDumpType.C_ARRAY:
        for insn in bpf:
            result.append(f"{{ 0x{insn[0]:x}, {insn[1]}, {insn[2]}, 0x{insn[3]:08x} }},")
        return '\n'.join(result)

    else:
        raise ValueError(f"unknown format: {format!r}")
