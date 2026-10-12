#pragma once
#include <vector>
#include <optional>
#include <cstdint>
#include <unordered_map>
#include <string>

typedef struct ks_struct ks_engine;

class Assembler
{
public:
    Assembler();
    ~Assembler();
    std::optional<std::vector<uint8_t>> Assemble(const char* const pszAsm, uint64_t nBaseAddress) const;

    bool RegisterSymbol(std::string symbolName, uint64_t value);
    std::optional<uint64_t> FindSymbol(const char* const pszSymbol);

private:

    static bool ksSymResolveCallback(void* pUserData, const char* pszSymName, uint64_t* pSym);

    std::unordered_map<std::string, uint64_t> m_PreResolvedSymbols;
    ks_engine* m_pEngine;
};