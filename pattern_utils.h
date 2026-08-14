#pragma once
#include <utility>
#include <vector>
#include <string_view>
#include <span>

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> PatternToMaskedBytes(const std::string_view input);
const uint8_t* FindPattern(std::span<const uint8_t> data, const std::vector<uint8_t>& vPatternBytes,
    const std::vector<uint8_t>& vPatternMask);