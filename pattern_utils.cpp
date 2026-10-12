#include "pattern_utils.h"
#include <charconv>

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> PatternToMaskedBytes(const std::string_view input)
{
    std::vector<uint8_t> vBytes;
    std::vector<uint8_t> vMask;

    const size_t inputLen = input.length();
    size_t i = 0;

    while (i < inputLen)
    {
        const char c = input[i];

        if (c == ' ')
        {
            i++;
            continue;
        }

        if (c == '?') {
            i++;
            if (i < inputLen && input[i] == '?') {
                i++;
            }

            vBytes.push_back(0);
            vMask.push_back(0x0);
            continue;
        }

        const char* pFirst = input.data() + i;
        const char* pLast = input.data() + std::min(i + 2, inputLen);

        uint32_t value;
        const std::from_chars_result result = std::from_chars(pFirst, pLast, value, 16);
        if (result.ec != std::errc{} || result.ptr == pFirst)
            return {};

        vBytes.push_back(static_cast<uint8_t>(value));
        vMask.push_back(0xFF);
        i += result.ptr - pFirst;
    }

    return { std::move(vBytes), std::move(vMask) };
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