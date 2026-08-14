from pathlib import Path

import lief
from utils import check_layout, parse_elf


def test_mipsel():
    elf = parse_elf("ELF/libdep_mipsel.so")
    assert elf.header.flags_list == [
        lief.ELF.PROCESSOR_FLAGS.MIPS_NOREORDER,
        lief.ELF.PROCESSOR_FLAGS.MIPS_PIC,
        lief.ELF.PROCESSOR_FLAGS.MIPS_CPIC,
        lief.ELF.PROCESSOR_FLAGS.MIPS_ABI_O32,
        lief.ELF.PROCESSOR_FLAGS.MIPS_ARCH_32R2,
    ]

    mips_abiflags = elf.get_section(".MIPS.abiflags")
    assert mips_abiflags is not None
    assert mips_abiflags.type == lief.ELF.Section.TYPE.MIPS_ABIFLAGS
    reginfo = elf.get_section(".reginfo")
    assert reginfo is not None
    assert reginfo.type == lief.ELF.Section.TYPE.MIPS_REGINFO

    assert elf.segments[1].type == lief.ELF.Segment.TYPE.MIPS_REGINFO

    rld_version = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_RLD_VERSION)
    assert rld_version is not None
    assert rld_version.value == 1
    mips_flags = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_FLAGS)
    assert mips_flags is not None
    assert mips_flags.value == 2
    mips_base = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_BASE_ADDRESS)
    assert mips_base is not None
    assert mips_base.value == 0
    mips_local_gotno = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_LOCAL_GOTNO)
    assert mips_local_gotno is not None
    assert mips_local_gotno.value == 9
    mips_symtabno = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_SYMTABNO)
    assert mips_symtabno is not None
    assert mips_symtabno.value == 21
    mips_unrefextno = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_UNREFEXTNO)
    assert mips_unrefextno is not None
    assert mips_unrefextno.value == 35
    mips_gotsym = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_GOTSYM)
    assert mips_gotsym is not None
    assert mips_gotsym.value == 3

    if lief.__extended__:
        inst = list(elf.disassemble("onload"))
        assert len(inst) == 191
        assert inst[0] is not None
        assert inst[0].to_string() == "0x000fa4: lui $gp, 0x2"
        assert inst[190] is not None
        assert inst[190].to_string() == "0x00129c: nop"


def test_add_library_mips_be(tmp_path: Path):
    """
    Adding a DT_NEEDED entry through add_library (see issue/)
    """
    elf = parse_elf("ELF/elf_reader.mips.elf")

    assert elf.header.identity_class == lief.ELF.Header.CLASS.ELF32
    assert elf.header.identity_data == lief.ELF.Header.ELF_DATA.MSB
    assert elf.header.machine_type == lief.ELF.ARCH.MIPS

    entry = elf.add_library("libfoo_be.so")
    assert entry.tag == lief.ELF.DynamicEntry.TAG.NEEDED
    assert entry.name == "libfoo_be.so"

    output = tmp_path / "elf_reader.mips.add_library.elf"
    elf.write(output)

    check_layout(output)

    new = parse_elf(output)
    assert new.get_library("libfoo_be.so") is not None
