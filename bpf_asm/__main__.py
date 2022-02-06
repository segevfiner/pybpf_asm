"""
Compile BPF assembly.
"""
import sys
import argparse

import bpf_asm


__package__ = "bpf_asm"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    format_group = parser.add_mutually_exclusive_group()
    format_group.add_argument('-f', '--format', default='DEFAULT',
                              choices=list(i.name for i in bpf_asm.BpfDumpType),
                              help="format to dump in")
    format_group.add_argument('-c', action='store_const', dest='format',
                              const='C_ARRAY', help='print C style')
    format_group.add_argument('-p', '--python', action='store_true',
                              help="dump as a Python list")
    parser.add_argument('input', type=argparse.FileType('r'),
                        help="bpf to assemble ('-' for stdin)")

    args = parser.parse_args()

    bpf = bpf_asm.assemble(args.input.read())

    if args.python:
        print(repr(bpf))
    else:
        print(bpf_asm.dumps(bpf, bpf_asm.BpfDumpType[args.format]))


if __name__ == "__main__":
    sys.exit(main())
