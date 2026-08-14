#pragma once
#include <vector>
#include <optional>

typedef struct ks_struct ks_engine;

class Assembler
{
public:
    Assembler();
    ~Assembler();
    std::optional<std::vector<uint8_t>> Assemble(const char* const pszAsm, uint64_t nBaseAddress) const;


private:
    ks_engine* m_pEngine;
};