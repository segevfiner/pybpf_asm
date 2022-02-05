cdef extern from "bpf_exp.yacc.h":
    void bpf_asm_compile(const char *str, int len, void (*write)(const char *str), bint cstyle)


cdef void write(const char *str):
    print(str)


def assemble(str, *, cstyle=False):
    str = str.encode()
    bpf_asm_compile(str, len(str), write, cstyle)
