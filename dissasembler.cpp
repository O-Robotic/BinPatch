#include "dissasembler.h"
#include <format>
#include <map>
#include <Zydis/Formatter.h>

extern bool g_bDebug;

ZydisFormatterFunc g_pfnDefaultFormatOperandMem;
ZydisFormatterFunc g_pfnDefaultFormatOperandImm;

static ZyanStatus MemPrintHook(const ZydisFormatter* pFormatter, ZydisFormatterBuffer* pFormatBuffer, ZydisFormatterContext* pContext)
{
    ZYAN_CHECK(g_pfnDefaultFormatOperandMem(pFormatter, pFormatBuffer, pContext));
    const ZydisDecodedOperand* pOp = pContext->operand;

    const ZyanBool bIsRipRelative = (pOp->mem.base == ZYDIS_REGISTER_RIP) || (pOp->mem.base == ZYDIS_REGISTER_EIP);

    if (bIsRipRelative)
    {
        ZyanU64 realAddress;
        ZyanString* pString;
        ZyanStringView view;
        char tmp[32];

        ZYAN_CHECK(ZydisCalcAbsoluteAddress(pContext->instruction, pOp, pContext->runtime_address, &realAddress));
        snprintf(tmp, sizeof(tmp), " (0x%llx)", realAddress);
        ZYAN_CHECK(ZydisFormatterBufferAppend(pFormatBuffer, ZYDIS_TOKEN_SYMBOL));
        ZYAN_CHECK(ZydisFormatterBufferGetString(pFormatBuffer, &pString));
        ZYAN_CHECK(ZyanStringViewInsideBuffer(&view, tmp));
        ZYAN_CHECK(ZyanStringAppend(pString, &view));
    }
   
    return ZYAN_STATUS_SUCCESS;
}

static ZyanStatus ImmPrintHook(const ZydisFormatter* pFormatter, ZydisFormatterBuffer* pFormatBuffer, ZydisFormatterContext* pContext)
{
    ZYAN_CHECK(g_pfnDefaultFormatOperandImm(pFormatter, pFormatBuffer, pContext));
    const ZydisDecodedOperand* pOp = pContext->operand;
    if (pOp->imm.is_relative)
    {
        ZyanString* pString;
        ZyanStringView view;
        char tmp[32];
        tmp[31] = '\0';
        snprintf(tmp, sizeof(tmp), " [rel%u]", pOp->imm.size);

        ZYAN_CHECK(ZydisFormatterBufferAppend(pFormatBuffer, ZYDIS_TOKEN_SYMBOL));
        ZYAN_CHECK(ZydisFormatterBufferGetString(pFormatBuffer, &pString));
        ZYAN_CHECK(ZyanStringViewInsideBuffer(&view, tmp));
        ZYAN_CHECK(ZyanStringAppend(pString, &view));

        if (pContext->runtime_address != ZYDIS_RUNTIME_ADDRESS_NONE)
        {
            ZyanU64 realAddress;
            ZYAN_CHECK(ZydisCalcAbsoluteAddress(pContext->instruction, pOp, pContext->runtime_address, &realAddress));
            snprintf(tmp, sizeof(tmp), " (0x%llx)", realAddress);

            ZYAN_CHECK(ZydisFormatterBufferAppend(pFormatBuffer, ZYDIS_TOKEN_SYMBOL));
            ZYAN_CHECK(ZydisFormatterBufferGetString(pFormatBuffer, &pString));
            ZYAN_CHECK(ZyanStringViewInsideBuffer(&view, tmp));
            ZYAN_CHECK(ZyanStringAppend(pString, &view));
        }

    }

    return ZYAN_STATUS_SUCCESS;
}

Disassembler::Disassembler()
{
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL, ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_BRANCHES, ZYAN_TRUE);

    const void* pNewCallback = (const void*)&MemPrintHook;
    ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_FORMAT_OPERAND_MEM, &pNewCallback);
    g_pfnDefaultFormatOperandMem = (ZydisFormatterFunc)pNewCallback;

    pNewCallback = (const void*)&ImmPrintHook;
    ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_FORMAT_OPERAND_IMM, &pNewCallback);
    g_pfnDefaultFormatOperandImm = (ZydisFormatterFunc)pNewCallback;
}

std::optional<size_t> Disassembler::GetStolenByteCount(std::span<const uint8_t> data, uint64_t requiredSize = 5) const 
{
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    ZyanUSize offset = 0;
    const ZyanUSize length = data.size();

    while (offset < requiredSize && offset < data.size())
    {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data.data() + offset, length - offset, &instruction, operands)))
        {
            printf("Disassembler::GetStolenByteCount: Failed to decode instruction\n");
            return std::nullopt;
        }

        offset += instruction.length;

        if (instruction.mnemonic == ZYDIS_MNEMONIC_RET)
        {
            const size_t bytesNeeded = requiredSize - offset;
            if (bytesNeeded > 0)
            {
                bool isSafePadding = true;
                uint8_t padByte;

                for (size_t i = 0; i < bytesNeeded; i++)
                {
                    const uint64_t padByteOffset = offset + i;
                    if (padByteOffset >= data.size()) {
                        return std::nullopt;
                    }

                    padByte = data[padByteOffset];
                    if (padByte != 0xCC && padByte != 0x90)
                    {
                        isSafePadding = false;
                        break;
                    }
                }

                if (!isSafePadding)
                {
                    printf("Not enough room for added instruction.\n");
                    return std::nullopt;
                }
            }
        }
    }

    if (offset < requiredSize)
    {
        return std::nullopt;
    }

    return offset;
}

size_t Disassembler::GetInstructionSize(std::span<const uint8_t> data) const
{
    ZydisDecodedInstruction instruction;

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, (ZydisDecoderContext*)ZYAN_NULL, data.data(), data.size(), &instruction)))
    {
        return size_t(-1);
    }

    return instruction.length;
}

std::string Disassembler::PrintInstructions(std::span<const uint8_t> instructionBuffer, const uint64_t baseAddress) const
{
    std::string outputString;
    char printBuffer[256];
    
    ZyanU64 offset = 0;

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, instructionBuffer.data() + offset, instructionBuffer.size() - offset, &instruction, operands)))
    {
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible, printBuffer, sizeof(printBuffer), baseAddress + offset, ZYAN_NULL);
        outputString.append(printBuffer);
        outputString.push_back('\n');
        offset += instruction.length;
    }
    
    return outputString;
}

const char* ZyanStatusToString(ZyanStatus status)
{
    switch (status)
    {
    case ZYAN_STATUS_SUCCESS:                  return "SUCCESS";
    case ZYAN_STATUS_FAILED:                   return "FAILED";
    case ZYAN_STATUS_TRUE:                     return "TRUE";
    case ZYAN_STATUS_FALSE:                     return "FALSE";
    case ZYAN_STATUS_INVALID_ARGUMENT:          return "INVALID_ARGUMENT";
    case ZYAN_STATUS_INVALID_OPERATION:         return "INVALID_OPERATION";
    case ZYAN_STATUS_NOT_FOUND:                 return "NOT_FOUND";
    case ZYAN_STATUS_OUT_OF_RANGE:              return "OUT_OF_RANGE";
    case ZYAN_STATUS_INSUFFICIENT_BUFFER_SIZE:  return "INSUFFICIENT_BUFFER_SIZE";
    case ZYAN_STATUS_NOT_ENOUGH_MEMORY:         return "NOT_ENOUGH_MEMORY";
    case ZYAN_STATUS_BAD_SYSTEMCALL:            return "BAD_SYSTEMCALL";
    case ZYAN_STATUS_OUT_OF_RESOURCES:          return "OUT_OF_RESOURCES";
    case ZYDIS_STATUS_NO_MORE_DATA:             return "ZYDIS_NO_MORE_DATA";
    case ZYDIS_STATUS_DECODING_ERROR:           return "ZYDIS_DECODING_ERROR";
    case ZYDIS_STATUS_INSTRUCTION_TOO_LONG:     return "ZYDIS_INSTRUCTION_TOO_LONG";
    case ZYDIS_STATUS_BAD_REGISTER:             return "ZYDIS_BAD_REGISTER";
    case ZYDIS_STATUS_ILLEGAL_LOCK:             return "ZYDIS_ILLEGAL_LOCK";
    case ZYDIS_STATUS_ILLEGAL_LEGACY_PFX:       return "ZYDIS_ILLEGAL_LEGACY_PFX";
    case ZYDIS_STATUS_ILLEGAL_REX:              return "ZYDIS_ILLEGAL_REX";
    case ZYDIS_STATUS_INVALID_MAP:              return "ZYDIS_INVALID_MAP";
    case ZYDIS_STATUS_MALFORMED_EVEX:           return "ZYDIS_MALFORMED_EVEX";
    case ZYDIS_STATUS_MALFORMED_MVEX:           return "ZYDIS_MALFORMED_MVEX";
    case ZYDIS_STATUS_INVALID_MASK:             return "ZYDIS_INVALID_MASK";
    case ZYDIS_STATUS_SKIP_TOKEN:               return "ZYDIS_SKIP_TOKEN";
    case ZYDIS_STATUS_IMPOSSIBLE_INSTRUCTION:   return "ZYDIS_IMPOSSIBLE_INSTRUCTION";

    default:
    {
        static char buf[256];
        buf[255] = '\0';
        snprintf(buf, sizeof(buf), "Unknown status (0x%08X, module=%u, code=%u)",
            status, ZYAN_STATUS_MODULE(status), ZYAN_STATUS_CODE(status));
        return buf;
    }
    }
}

std::vector<uint8_t> Disassembler::RelocateInstructions(const std::vector<uint8_t>& bytes, uint64_t originalVA, uint64_t newVA) const
{
    uint64_t readOffset = 0;
    uint64_t newInstructionsOffset = 0;
    std::vector<uint8_t> newInstructions;

    while (readOffset < bytes.size())
    {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes.data() + readOffset, bytes.size() - readOffset, &instruction, operands)))
        {
            return {};
        }

        ZydisEncoderRequest encReq;
        const ZyanStatus reqStatus = ZydisEncoderDecodedInstructionToEncoderRequest(
            &instruction, operands, instruction.operand_count_visible, &encReq);

        if (reqStatus != ZYAN_STATUS_SUCCESS)
        {
            char errBuff[256];
            printf("Disassembler::RelocateInstructions: Failed to create encoder request err: %s\n", ZyanStatusToString(reqStatus));
            if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible, errBuff, sizeof(errBuff), originalVA + readOffset, ZYAN_NULL)))
            {
                return {};
            }

            printf("%s", errBuff);
            return {};
        }

        bool bNeedsReencoding = false;

        for (size_t i = 0; i < instruction.operand_count_visible; i++)
        {
            const ZydisDecodedOperand& operand = operands[i];

            if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.base == ZYDIS_REGISTER_RIP)
            {
                uint64_t newVAForOperand = 0;
                ZydisCalcAbsoluteAddress(&instruction, &operand, originalVA + readOffset, &newVAForOperand);

                const int64_t insnOffsetDisp = static_cast<int64_t>(newVAForOperand - (newVA + newInstructionsOffset + instruction.length));
                if (insnOffsetDisp < INT32_MIN || insnOffsetDisp > INT32_MAX)
                {
                    fprintf(stderr, "Unsupported relocation needed\n");
                    return {};
                }

                encReq.operands[i].mem.displacement = insnOffsetDisp;
                bNeedsReencoding = true;
            }
            else if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative)
            {
                uint64_t newVAForOperand = 0;
                ZydisCalcAbsoluteAddress(&instruction, &operand, originalVA + readOffset, &newVAForOperand);

                const bool bInstructionIsBranching = (instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                    instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR);

                //This needs to be done better
                int64_t nAddressDisplacement = static_cast<int64_t>(newVAForOperand - (newVA + newInstructionsOffset + instruction.length));
                
                bool bFits8BitRel = (nAddressDisplacement >= INT8_MIN && nAddressDisplacement <= INT8_MAX);

                size_t newInsnLength = instruction.length;

                // If we need to resize a branch then we need to know if its a conditional or not
                // Conditional branches need 6 bytes when expanded to rel32 but unconditional branches need 5 bytes
                if (bInstructionIsBranching && !bFits8BitRel)
                {
                    const bool bIsConditionalJump = (instruction.mnemonic >= ZYDIS_MNEMONIC_JB && instruction.mnemonic <= ZYDIS_MNEMONIC_JZ);
                    newInsnLength = bIsConditionalJump ? 6 : 5;
                }

                //Recalculate the new offset accounting for the potentially larger instruction size
                nAddressDisplacement = static_cast<int64_t>(newVAForOperand - (newVA + newInstructionsOffset + newInsnLength));

                if (bInstructionIsBranching)
                {
                    bFits8BitRel = (nAddressDisplacement >= INT8_MIN && nAddressDisplacement <= INT8_MAX);
                    encReq.branch_type = bFits8BitRel ? ZYDIS_BRANCH_TYPE_SHORT : ZYDIS_BRANCH_TYPE_NEAR;
                    encReq.branch_width = bFits8BitRel ? ZYDIS_BRANCH_WIDTH_8 : ZYDIS_BRANCH_WIDTH_32;
                }

                if (nAddressDisplacement < INT32_MIN || nAddressDisplacement > INT32_MAX)
                {
                    fprintf(stderr, "Unsupported relocation needed\n");
                    return {};
                }

                encReq.operands[i].imm.s = nAddressDisplacement;
                bNeedsReencoding = true;
            }
        }


        if (bNeedsReencoding)
        {
            uint8_t newInstructionBuffer[ZYDIS_MAX_INSTRUCTION_LENGTH];
            ZyanUSize newSize = sizeof(newInstructionBuffer);

            const ZyanStatus status = ZydisEncoderEncodeInstruction(&encReq, newInstructionBuffer, &newSize);
            if (!ZYAN_SUCCESS(status))
            {
                printf("ZydisEncoderEncodeInstruction failed: status=%s\n", ZyanStatusToString(status));
                return {};
            }

            newInstructions.insert(newInstructions.end(), newInstructionBuffer, newInstructionBuffer + newSize);
            newInstructionsOffset += newSize;
            readOffset += instruction.length;
        }
        else
        {
            newInstructions.insert(newInstructions.end(), bytes.data() + readOffset, bytes.data() + readOffset + instruction.length);
            newInstructionsOffset += instruction.length;
            readOffset += instruction.length;
        }
    }

    return newInstructions;
}
