from libc.stdlib cimport free
from libc.stdint cimport uint8_t, uint16_t, uint32_t


class Error(Exception):
    pass


cdef extern from "bpf_exp.yacc.h":
    struct sock_filter:
        uint16_t	code   # Actual filter code
        uint8_t	    jt	   # Jump true
        uint8_t	    jf	   # Jump false
        uint32_t	k      # Generic multiuse field

    int bpf_asm_compile(const char *str, int len, sock_filter (**out), const char **error)


def assemble(str):
    cdef sock_filter *out = NULL
    cdef char *error = NULL

    str = str.encode()
    result = bpf_asm_compile(str, len(str), &out, &error)
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
