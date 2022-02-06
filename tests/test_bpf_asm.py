import bpf_asm


TEST_BPF = [(40, 0, 0, 12), (21, 0, 1, 2048), (6, 0, 0, 65536), (6, 0, 0, 0)]
TEST_BPF_ASM = """\
    ldh [12]
    jeq #0x800, accept, drop
accept:
    ret #65536
drop:
    ret #0
"""

def test_assemble():
    assert bpf_asm.assemble(TEST_BPF_ASM) == TEST_BPF


def test_dumps_default():
    assert bpf_asm.dumps(TEST_BPF) == "4,40 0 0 12,21 0 1 2048,6 0 0 65536,6 0 0 0"


def test_dumps_multiline():
    assert bpf_asm.dumps(TEST_BPF, bpf_asm.BpfDumpType.MULTILINE) == "4\n40 0 0 12\n21 0 1 2048\n6 0 0 65536\n6 0 0 0"


def test_dumps_c_array():
    assert bpf_asm.dumps(TEST_BPF, bpf_asm.BpfDumpType.C_ARRAY) == \
        "{ 0x28, 0, 0, 0x0000000c },\n{ 0x15, 0, 1, 0x00000800 },\n{ 0x6, 0, 0, 0x00010000 },\n{ 0x6, 0, 0, 0x00000000 },"
