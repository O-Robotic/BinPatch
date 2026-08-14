#include "pattern_utils.h"
#include <immintrin.h>
#include <assert.h>

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> PatternToMaskedBytes(const std::string_view input)
{
    std::vector<uint8_t> vBytes;
    std::vector<uint8_t> vMask;

    const char* const pszPatternEnd = input.data() + input.length();

    for (const char* pszCurrentByte = input.data(); pszCurrentByte < pszPatternEnd; ++pszCurrentByte)
    {
        if (*pszCurrentByte == '?')
        {
            ++pszCurrentByte;

            if (*pszCurrentByte == '?')
            {
                ++pszCurrentByte;
            }

            vBytes.push_back(0);
            vMask.push_back(0x00);
        }
        else
        {
            vBytes.push_back(static_cast<uint8_t>(strtoul(pszCurrentByte, const_cast<char**>(&pszCurrentByte), 16)));
            vMask.push_back(0xFF);
        }
    }

    return std::make_pair(vBytes, vMask);
};

const uint8_t* FindPattern(std::span<const uint8_t> data, const std::vector<uint8_t>& vPatternBytes,
    const std::vector<uint8_t>& vPatternMask) {

    if (vPatternBytes.size() != vPatternMask.size())
        return nullptr;
    if (data.size() < vPatternMask.size())
        return nullptr;

    for (size_t i = 0; i <= data.size() - vPatternBytes.size(); i++)
    {
        for (size_t j = 0; j < vPatternBytes.size(); j++)
        {
            if ((data[i + j] & vPatternMask[j]) != vPatternBytes[j]) {
                goto outerloop;
            }
        }
        return &data[i];
    outerloop:;
    }

    return nullptr;
}