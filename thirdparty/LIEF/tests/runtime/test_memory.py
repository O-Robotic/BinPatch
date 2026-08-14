import lief
import pytest
from lief.runtime import Memory

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)


@pytest.mark.runtime
def test_basic():
    chunk = Memory.mmap(
        0x4000, Memory.ANONYMOUS | Memory.PRIVATE, Memory.READ | Memory.WRITE
    )
    assert chunk is not None

    assert chunk.addr == lief.to_int(chunk.addr_ptr)
    assert chunk.size == 0x4000
    assert chunk.permissions == Memory.READ | Memory.WRITE
    assert Memory.perm_str(chunk.permissions) == "rw-"

    assert chunk.page_start < chunk.page_end
    chunk.cache_flush()
    assert str(chunk) != ""

    Memory.write_u32(0xDEADC0DE, chunk.addr)
    assert Memory.read_u32(chunk.addr) == 0xDEADC0DE

    chunk.make_x()
    chunk.make_rw()
    chunk.make_rx()
    chunk.make_rwx()
    chunk.make_ro()

    assert Memory.munmap(chunk)
