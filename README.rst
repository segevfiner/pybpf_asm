pybpf_asm
=========
.. image:: https://img.shields.io/pypi/v/bpf_asm.svg
   :target: https://pypi.org/project/bpf_asm/
   :alt: PyPI

.. image:: https://github.com/segevfiner/pybpf_asm/actions/workflows/build-and-test.yml/badge.svg
   :target: https://github.com/segevfiner/pybpf_asm/actions/workflows/build-and-test.yml
   :alt: Build & Test

.. image:: https://github.com/segevfiner/pybpf_asm/actions/workflows/docs.yml/badge.svg
   :target: https://segevfiner.github.io/pybpf_asm/
   :alt: Docs

Python BPF Assembler.

Based on the BPF assembler in Linux sources.

Installations
-------------
Wheels are available.

To build from source you need a relatively recent Flex & Bison:

* On Windows, you can use `winflexbison <https://github.com/lexxmark/winflexbison>`_.
* On macOS (and sometimes on Linux, on older distributions), you can install them from `Homebrew <https://brew.sh/>`_. Note that you might have to add Homebrew's version to the front of the ``PATH``, e.g. ``PATH="$(brew --prefix)/opt/flex/bin:$(brew --prefix)/opt/bison/bin:$PATH"``.

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
