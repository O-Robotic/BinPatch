#include "assembler.h"
#include <stdio.h>
#include "thirdparty/keystone/include/keystone/x86.h"

Assembler::Assembler()
{
    if (ks_open(KS_ARCH_X86, KS_MODE_64, &m_pEngine) != KS_ERR_OK)
    {
        m_pEngine = nullptr;
    }
}

Assembler::~Assembler()
{
    if (m_pEngine) ks_close(m_pEngine);
}

std::optional<std::vector<uint8_t>> Assembler::Assemble(const char* const pszAsm, uint64_t nBaseAddress) const
{
    if (!m_pEngine)
        return std::nullopt;

    uint8_t* pEncodeBuffer;
    size_t nEncodeSize = 0;
    size_t nStatements = 0;
    
    int ret = ks_asm(m_pEngine, pszAsm, nBaseAddress,
        &pEncodeBuffer, &nEncodeSize, &nStatements);

    if (ret != 0)
    {
        fprintf(stderr, "Failed to assemble code err: %s\nFailed statement idx %zu\n", ks_strerror(ks_errno(m_pEngine)), nStatements);
        ks_free(pEncodeBuffer);
        return std::nullopt;
    }

    std::vector<uint8_t> bytes(pEncodeBuffer, pEncodeBuffer + nEncodeSize);
    ks_free(pEncodeBuffer);
    return bytes;
}
