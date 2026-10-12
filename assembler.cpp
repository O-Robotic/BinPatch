#include "assembler.h"
#include <stdio.h>
#include "thirdparty/keystone/include/keystone/x86.h"

Assembler::Assembler()
{
    if (ks_open(KS_ARCH_X86, KS_MODE_64, &m_pEngine) != KS_ERR_OK)
    {
        m_pEngine = nullptr;
    }

    ks_setsymbolcallback(m_pEngine, ksSymResolveCallback, this);
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

std::optional<uint64_t> Assembler::FindSymbol(const char* const pszSymbol)
{
    const auto it = m_PreResolvedSymbols.find(pszSymbol);
    if (it == m_PreResolvedSymbols.end())
        return std::nullopt;
    return it->second;
}

bool Assembler::RegisterSymbol(std::string symbolName, uint64_t value)
{
    if (m_PreResolvedSymbols.contains(symbolName))
        return false;

    m_PreResolvedSymbols.insert({ std::move(symbolName), value });
    return true;
}

bool Assembler::ksSymResolveCallback(void* pUserData, const char* pszSymName, uint64_t* pValue)
{
    Assembler* const pAssembler = reinterpret_cast<Assembler*>(pUserData);
    const auto symbol = pAssembler->FindSymbol(pszSymName);
    if (!symbol)
        return false;

    *pValue = *symbol;
    return true;
}