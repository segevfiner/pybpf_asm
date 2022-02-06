# cython: language_level=3str

import enum
from libc.stdlib cimport free
from libc.stdint cimport uint8_t, uint16_t, uint32_t


class Error(Exception):
    pass



class BpfDumpType(enum.IntEnum):
    DEFAULT = 0
    MULTILINE = 1
    C_ARRAY = 2


cdef extern from "bpf_exp.yacc.h":
    struct sock_filter:
        uint16_t	code   # Actual filter code
        uint8_t	    jt	   # Jump true
        uint8_t	    jf	   # Jump false
        uint32_t	k      # Generic multiuse field

    int bpf_asm_compile(const char *str, int len, sock_filter (**out), const char **error)


def assemble(str: str) -> [(int, int, int, int)]:
    """Assemble BPF *str*."""
    cdef sock_filter *out = NULL
    cdef char *error = NULL

    strbytes = str.encode()
    result = bpf_asm_compile(strbytes, len(strbytes), &out, &error)
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


def dumps(bpf: [(int, int, int, int)], format=BpfDumpType.DEFAULT) -> str:
    """Dump *bpf* to a str in *format*."""
    result = []

    if format == BpfDumpType.DEFAULT:
        result.append(f"{len(bpf)},")

        for insn in bpf[:-2]:
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
            result.append(f"{{ 0x{insn[0]:x} {insn[1]} {insn[2]} 0x{insn.k[3]:08x} }},")
        return '\n'.join(result)
