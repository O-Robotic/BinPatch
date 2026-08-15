#pragma once
#include "zydis/Zydis.h"
#include <string>
#include <span>
#include <vector>
#include <optional>
#include <cstdint>

class Disassembler
{
public:
    Disassembler();

    size_t GetInstructionSize(std::span<const uint8_t> data) const;
    std::string PrintInstructions(std::span<const uint8_t> instructionBuffer, const uint64_t baseAddress) const;

    std::optional<size_t> GetStolenByteCount(std::span<const uint8_t> data, uint64_t requiredSize) const;
    std::vector<uint8_t> RelocateInstructions(const std::vector<uint8_t>& bytes, uint64_t originalVA, uint64_t newVA) const;

private:
    ZydisFormatter formatter;
    ZydisDecoder decoder;
};