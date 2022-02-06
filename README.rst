pybpf_asm
=========
\:warning: WIP :warning:

Python BPF Assembler.

Based on the BPF assembler in Linux sources.

Usage
-----
.. code-block:: python

    import bpf_asm


    ASM = """\
        ldh [12]
        jeq #0x800, accept, drop
    accept:
        ret #65536
    drop:
        ret #0
    """

    print(bpf_asm.assemble(ASM))


Or use the ``pybpf_asm`` script. See ``pybpf_asm --help`` for usage.

License
-------
GPL-2.0-only.
