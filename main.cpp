#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <utility>
#include <span>
#include <format>
#include <filesystem>
#include <cstdint>

#include "pattern_utils.h"
#include "assembler.h"
#include "dissasembler.h"

#include <LIEF/LIEF.hpp>
#include <LIEF/PE.hpp>

#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/Import.hpp"
#include <inttypes.h>

#include <c4/base64.hpp>
#include <ryml.hpp>
#include "yaml_utils.h"

#define BP_ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))

bool g_bDebug = false;

struct CodePatch {
    std::vector<uint8_t> m_StolenBytes;
    std::vector<uint8_t> m_PatchBytes;
    uint64_t m_nPatchVA = 0;
};

enum class StolenByteRestorePos : uint8_t { Leading = 0, Trailing };

struct TrampolinePatch
{
    std::vector<uint8_t> m_StolenBytes;
    std::string m_PatchASM;
    uint64_t m_nPatchVA = 0;
    size_t m_nCaveSize = 0;
    StolenByteRestorePos m_RestorePos;
    bool m_bJumpBack;
    bool m_bKeepStolenInstructions;
};

static LIEF::PE::Section* AllocateCaveSection(LIEF::PE::Binary& binary, size_t totalSize)
{
    LIEF::PE::Section caveSection(".cave");
    caveSection.content(std::vector<uint8_t>(totalSize, 0xCC)); // int 3 filler
    caveSection.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
    caveSection.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_READ);
    caveSection.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::CNT_CODE);

    LIEF::PE::Section* added = binary.add_section(caveSection);
    return added;
}

struct CodePatchCtx
{
public:
    explicit CodePatchCtx(LIEF::PE::Binary& bin) : m_LoadedPE(bin) {
    }

    bool SetupCodePatch(const ryml::ConstNodeRef& patchJson)
    {
        std::string_view segment;
        std::string patchASM;
        std::string_view mode;
        std::string_view sig;

        if (!YamlGetStringView(patchJson, "segment", segment) || segment.empty())
        {
            fprintf(stderr, "Invalid patch segment def\n");
            return false;
        }

        if (!YamlGetString(patchJson, "patch", patchASM) || patchASM.empty())
        {
            fprintf(stderr, "Invalid patch def\n");
            return false;
        }

        if (!YamlGetStringView(patchJson, "mode", mode) || mode.empty())
        {
            fprintf(stderr, "Invalid mode def\n");
            return false;
        }

        if (!YamlGetStringView(patchJson, "sig", sig) || sig.empty())
        {
            fprintf(stderr, "Invalid sig def\n");
            return false;
        }

        LIEF::PE::Section* pSection = m_LoadedPE.get_section(segment);

        if (!pSection) {
            std::cout << "Could not find section " << segment << std::endl;
            return false;
        }

        auto sectionData = pSection->writable_content();

        const uint8_t* pPatchAddress = nullptr;        
        const auto [bytes, mask] = PatternToMaskedBytes(sig);
        pPatchAddress = FindPattern(sectionData, bytes, mask);

        if (!pPatchAddress)
        {
            std::cout << std::format("Could not find pattern [{}] in segment {}", sig, segment) << std::endl;
            return false;
        }
        
        std::cout << std::format("Building code patch for [{}]", sig) << std::endl;
        
        const uint64_t offset = static_cast<uint64_t>(pPatchAddress - sectionData.data());
        const uint64_t patchVA = m_LoadedPE.imagebase() + pSection->virtual_address() + offset;
        const size_t sectionRemaining = sectionData.size() - offset;

        if (mode == "replace")
        {
            if (!SetupInlinePatch(patchASM.c_str(), pPatchAddress, patchVA, sectionRemaining))
            {
                printf("Failed to setup inline patch\n");
                return false;
            }   
        }
        else if (mode == "insert")
        {
            bool bJumpBack = YamlGetBool(patchJson, "jump_back", true);
            bool bKeepStolen = YamlGetBool(patchJson, "keep_stolen", true);
            StolenByteRestorePos byteRestorePos = StolenByteRestorePos::Leading;

            std::string_view byteRestorePosStr;
            if (YamlGetStringView(patchJson, "byte_restore_pos", byteRestorePosStr))
            {
                if(byteRestorePosStr == "trailing") {
                    byteRestorePos = StolenByteRestorePos::Trailing;
                }
            }

            if (!SetupTrampolinePatch(patchASM, pPatchAddress, patchVA, sectionRemaining, bJumpBack, bKeepStolen, byteRestorePos))
            {
                printf("Failed to setup trampoline patch\n");
                return false;
            }
        }
        else
        {
            assert(0);
            std::cout << "Unsupported mode " << mode << std::endl;
            return false;
        }

        return true;
    }

    bool SetupInlinePatch(const char* const pszPatchASM, const uint8_t* pPatchAddress, uint64_t patchVA, size_t sectionRemaining)
    {
        CodePatch patch;

        const std::optional<std::vector<uint8_t>> assembledRes = m_Assembler.Assemble(pszPatchASM, patchVA);
        if (!assembledRes)
            return false;

        const std::vector<uint8_t>& assembled = *assembledRes;

        if (g_bDebug)
        {
            const std::string printed = m_Dissasembler.PrintInstructions(assembled, patchVA);
            std::cout << printed << std::endl;
        }
       
        const size_t window = std::min<size_t>(assembled.size() + 16, sectionRemaining);
        const std::span<const uint8_t> patchableBytes = { pPatchAddress, window };

        const std::optional<size_t> result = m_Dissasembler.GetStolenByteCount(patchableBytes, assembled.size());
        
        if (!result)
            return false;

        patch.m_nPatchVA = patchVA;
        patch.m_PatchBytes.assign(*result, 0x90);
        memcpy(patch.m_PatchBytes.data(), assembled.data(), assembled.size());

        m_InlinePatches.push_back(patch);
        return true;
    }

    bool SetupTrampolinePatch(std::string patchASM, const uint8_t* pPatchAddress,
        uint64_t patchVA, size_t sectionRemaining, bool bJumpBack, bool bKeepStolenInstructions, StolenByteRestorePos restorePos)
    {
        TrampolinePatch tp;
        tp.m_PatchASM = std::move(patchASM);

        const std::optional<std::vector<uint8_t>> assembledRes = m_Assembler.Assemble(tp.m_PatchASM.c_str(), patchVA);

        if (!assembledRes)
            return false;

        const std::vector<uint8_t>& assembled = *assembledRes;

        const size_t window = std::min<size_t>(5 + 16, sectionRemaining);
        const std::span<const uint8_t> patchableBytes = { pPatchAddress, window };

        const std::optional<size_t> res = m_Dissasembler.GetStolenByteCount(patchableBytes, 5);
        if (!res)
            return false;

        std::vector<uint8_t> stolenBytesVec(pPatchAddress, pPatchAddress + *res);

        size_t reloactedSize = 0;
        if (bKeepStolenInstructions)
        {
            const std::vector<uint8_t> relocated = m_Dissasembler.RelocateInstructions(stolenBytesVec, patchVA, patchVA + 16);
            reloactedSize = relocated.size();
        }

        //Rough size guess for jump back
        const size_t caveSize = reloactedSize + assembled.size() + 5;
        const size_t alignedOffset = BP_ALIGN_UP(m_nEstimatedCaveSize, 16);

        tp.m_nPatchVA = patchVA;
        tp.m_StolenBytes = std::move(stolenBytesVec);
        tp.m_bJumpBack = bJumpBack;
        tp.m_bKeepStolenInstructions = bKeepStolenInstructions;
        tp.m_RestorePos = restorePos;

        m_nEstimatedCaveSize = alignedOffset + caveSize;
        m_TrampolinePatches.push_back(tp);
        return true;
    }

    inline LIEF::PE::Binary& Binary() { return m_LoadedPE; }

    bool ApplyInlinePatches() const
    {
        for (auto& patch : m_InlinePatches)
        {
            m_LoadedPE.patch_address(patch.m_nPatchVA, patch.m_PatchBytes, LIEF::Binary::VA_TYPES::VA);
        }

        return true;
    }

    bool ApplyTrampolinePatches() const
    {
        if (m_TrampolinePatches.empty() || !m_nEstimatedCaveSize)
            return true;

        //Rough estimate of the size since after relocation the size might change
        LIEF::PE::Section* caveSection = AllocateCaveSection(m_LoadedPE, m_nEstimatedCaveSize);
        const uint64_t caveBaseVA = m_LoadedPE.imagebase() + caveSection->virtual_address();

        auto writableSpan = caveSection->writable_content();
        size_t nCaveOffset = 0;

        for (auto& patch : m_TrampolinePatches)
        {
            const uint64_t caveVA = caveBaseVA + nCaveOffset;

            std::vector<uint8_t> body;

            if (patch.m_RestorePos == StolenByteRestorePos::Leading)
            {
                std::vector<uint8_t> relocated;

                if (patch.m_bKeepStolenInstructions)
                {
                    relocated = m_Dissasembler.RelocateInstructions(patch.m_StolenBytes, patch.m_nPatchVA, caveVA);
                }

                const uint64_t injectedVA = caveVA + relocated.size();
                const std::optional<std::vector<uint8_t>> assembledRes = m_Assembler.Assemble(patch.m_PatchASM.c_str(), injectedVA);
                if (!assembledRes)
                    return false;

                body = std::move(relocated);
                body.insert(body.end(), assembledRes->begin(), assembledRes->end());
            }
            else
            {
                std::optional<std::vector<uint8_t>> injectedRes = m_Assembler.Assemble(patch.m_PatchASM.c_str(), caveVA);
                const uint64_t relocatedVA = caveVA + injectedRes->size();

                std::vector<uint8_t> relocated;
                if (patch.m_bKeepStolenInstructions)
                {
                    relocated = m_Dissasembler.RelocateInstructions(patch.m_StolenBytes, patch.m_nPatchVA, relocatedVA);

                    if (relocated.empty())
                    {
                        fprintf(stderr, "Failed to relocate instruction data\n");
                        return false;
                    }

                }

                body = std::move(*injectedRes);
                body.insert(body.end(), relocated.begin(), relocated.end());
            }

            if (patch.m_bJumpBack)
            {
                const uint64_t jmpSite = caveVA + body.size();
                const uint64_t backTarget = patch.m_nPatchVA + patch.m_StolenBytes.size();
                body.push_back(0xE9);
                const int32_t rel = static_cast<int32_t>(backTarget - (jmpSite + 5));
                uint8_t relBytes[4];
                memcpy(relBytes, &rel, 4);
                body.insert(body.end(), relBytes, relBytes + sizeof(relBytes));
            }

            if (nCaveOffset + body.size() > writableSpan.size())
            {
                size_t nNewSize = BP_ALIGN_UP(nCaveOffset + body.size(), 512);
                caveSection->reserve(nNewSize, 0xCC);
                caveSection->size(nNewSize);
                caveSection->virtual_size((uint32_t)nNewSize);
                writableSpan = caveSection->writable_content();
            }

            assert(writableSpan.data() + nCaveOffset + body.size() <= writableSpan.end());
            memcpy(writableSpan.data() + nCaveOffset, body.data(), body.size());
            nCaveOffset = BP_ALIGN_UP(body.size() + nCaveOffset, 16);

            std::vector<uint8_t> jumpOut(patch.m_StolenBytes.size(), 0x90);
            jumpOut[0] = 0xE9;
            const int32_t outRel = static_cast<int32_t>(caveVA - (patch.m_nPatchVA + 5));
            memcpy(&jumpOut[1], &outRel, sizeof(outRel));
            m_LoadedPE.patch_address(patch.m_nPatchVA, jumpOut);
        }

        return true;
    }

    bool ApplyPatches()
    {
        if (!ApplyInlinePatches())
            return false;
        if (!ApplyTrampolinePatches())
            return false;

        return true;
    }

    inline bool RegisterSymbol(std::string symbolName, uint64_t symbolValue)
    {
        return m_Assembler.RegisterSymbol(std::move(symbolName), symbolValue);
    }

private:
    LIEF::PE::Binary& m_LoadedPE;
    std::vector<CodePatch> m_InlinePatches;
    std::vector<TrampolinePatch> m_TrampolinePatches;
    Disassembler m_Dissasembler;
    Assembler m_Assembler;
    uint64_t m_nEstimatedCaveSize = 0;
};



static bool AddImportEntry(LIEF::PE::Import& import_, const ryml::ConstNodeRef& entry)
{
    if (!entry.is_map())
        return false;

    uint16_t ordinal;
    std::string_view name;
    bool bOrdinalNodeValid = YamlGetNumeric(entry, "ordinal", ordinal);
    bool bNameNodeValid = YamlGetStringView(entry, "name", name);

    if (bOrdinalNodeValid == bNameNodeValid)
    {
        fprintf(stderr, "Import definition must have either a name or ordinal\n");
        return false;
    }

    if (bOrdinalNodeValid)
    {
        if (ordinal < 1)
        {
            fprintf(stderr, "Invalid ordinal specified for entry %" PRIu32 "\n", ordinal);
            return false;
        }

        printf("Adding import entry with ordinal %" PRIu32 "\n", ordinal);
        LIEF::PE::ImportEntry importEntry((1ull << 63) | ordinal, LIEF::PE::PE_TYPE::PE32_PLUS);
        import_.add_entry(importEntry);
    }
    else if (bNameNodeValid)
    {
        if (name.empty())
        {
            fprintf(stderr, "Empty name specified for entry\n");
            return false;
        }

        printf("Adding import entry with name %.*s\n", static_cast<int>(name.length()), name.data());
        import_.add_entry(name);
    }

    return true;
}

static bool RemoveImportEntry(LIEF::PE::Import& import_, ryml::ConstNodeRef entry)
{
    const bool bHasOrdinal = entry.has_child("ordinal");
    const bool bHasName = entry.has_child("name");

    if (bHasOrdinal == bHasName)
    {
        fprintf(stderr, "Import definition must have either a name or ordinal\n");
        return false;
    }

    if (bHasOrdinal)
    {
        uint32_t ordinal;
        if (!YamlGetNumeric(entry, "ordinal", ordinal))
        {
            fprintf(stderr, "Invalid ordinal specified\n");
            return false;
        }

        if (ordinal < 1 || ordinal > UINT16_MAX)
        {
            fprintf(stderr, "Invalid ordinal specified %" PRIu32 "\n", ordinal);
            return false;
        }

        if (import_.remove_entry(ordinal))
        {
            printf("Removed import entry with ordinal %" PRIu32 "\n", ordinal);
        }
        else
        {
            printf("Failed to remove import entry with ordinal %" PRIu32 "\n", ordinal);
            return false;
        }
    }
    else
    {
        std::string_view name;
        if (!YamlGetStringView(entry, "name", name))
        {
            fprintf(stderr, "Invalid Name specified for import removal\n");
            return false;
        }

        if (name.empty())
        {
            fprintf(stderr, "Empty name specified for entry\n");
            return false;
        }

        if (import_.remove_entry(name))
        {
            printf("Removed import entry with name %.*s\n", static_cast<int>(name.length()), name.data());
        }
        else
        {
            printf("Failed to remove import entry with name %.*s\n", static_cast<int>(name.length()), name.data());
            return false;
        }
    }

    return true;
}

static bool ProcessImportAdd(LIEF::PE::Binary& binary, const ryml::ConstNodeRef importDef)
{
    if (!importDef.is_map())
    {
        fprintf(stderr, "Import definition must be a map\n");
        return false;
    }

    std::string_view moduleName;
    if (!YamlGetStringView(importDef, "module", moduleName))
    {
        fprintf(stderr, "No module specified for adding an import\n");
        return false;
    }

    const ryml::ConstNodeRef entries = importDef.find_child("entries");
    if (entries.invalid() || !entries.is_seq())
    {
        fprintf(stderr, "Import definition must have at least one entry\n");
        return false;
    }

    printf("Adding import %.*s\n", static_cast<int>(moduleName.length()), moduleName.data());
    LIEF::PE::Import& new_import = binary.add_import(moduleName);

    for (const ryml::ConstNodeRef entry : entries.children())
    {
        if (!AddImportEntry(new_import, entry))
            return false;
    }

    return true;
}

static bool ProcessImportEdit(LIEF::PE::Binary& binary, const ryml::ConstNodeRef importDef)
{
    std::string_view moduleName;
    if (!YamlGetStringView(importDef, "module", moduleName))
    {
        fprintf(stderr, "No module specified for modifying an import\n");
        return false;
    }

    if (YamlGetBool(importDef, "remove", false))
    {
        binary.remove_import(moduleName);
        return false;
    }

    LIEF::PE::Import* pImport = binary.get_import(moduleName);

    if (!pImport)
    {
        fprintf(stderr, "No import exists for module %.*s\n", static_cast<int>(moduleName.length()), moduleName.data());
        return false;
    }

    ryml::ConstNodeRef entries = importDef.find_child("entries");
    if (entries.invalid() || !entries.is_seq() || !entries.num_children())
    {
        fprintf(stderr, "Import modification must have at least one entry\n");
        return false;
    }

    for (const auto& entry : entries.children())
    {
        std::string_view op;
        if (!YamlGetStringView(entry, "op", op))
        {
            fprintf(stderr, "Import entry modification specified with no op\n");
            continue;
        }

        if (op == "add")
        {
            if (!AddImportEntry(*pImport, entry))
                return false;
        }
        else if (op == "remove")
        {
            if (!RemoveImportEntry(*pImport, entry))
                return false;
        }
        else
        {
            assert(0);
        }
    }

    return true;
}

static bool ProcessImport(LIEF::PE::Binary& binary, const ryml::ConstNodeRef importDef)
{
    std::string_view mode;
    if (!YamlGetStringView(importDef, "mode", mode))
    {
        return false;
    }
    
    if (mode == "add")
    {
        return ProcessImportAdd(binary, importDef);
    }
    
    if(mode == "edit")
    {
        return ProcessImportEdit(binary, importDef);
    }
    
    assert(0);
    return false;
}

static bool ProcessExportAdd(LIEF::PE::Binary& binary, const ryml::ConstNodeRef exportDef)
{
    std::string_view name;
    uint16_t ordinal;

    const bool bOrdinalSpecified = YamlGetNumeric(exportDef, "ordinal", ordinal);
    const bool bNameSpecified = YamlGetStringView(exportDef, "name", name);

    if (bOrdinalSpecified == bNameSpecified)
    {
        fprintf(stderr, "Export add must have either a name or ordinal\n");
        return false;
    }

    LIEF::PE::Export* pExports;

    uint32_t rva = 0;
    ryml::ConstNodeRef rva_sig;

    if (YamlGetMap(exportDef, "rva_sig", rva_sig))
    {
        std::string_view sectionName;
        if (!YamlGetStringView(rva_sig, "section", sectionName))
        {
            fprintf(stderr, "No section name specified for new export entry\n");
            return false;
        }

        std::string_view sigString;
        if (!YamlGetStringView(rva_sig, "sig", sigString))
        {
            fprintf(stderr, "No sig specified for new export entry\n");
            return false;
        }

        if (sectionName.empty() || sigString.empty())
        {
            fprintf(stderr, "Bad rva_sig definition for export\n");
            return false;
        }

        LIEF::PE::Section* pSection = binary.get_section(sectionName);
        if (!pSection)
        {
            fprintf(stderr, "Section specified in rva_sig definition for export not found\n");
            return false;
        }

        std::span<const uint8_t> sectionData = pSection->writable_content();

        const auto [bytes, mask] = PatternToMaskedBytes(sigString);
        const uint8_t* pAddress = FindPattern(sectionData, bytes, mask);

        const uint32_t offset = static_cast<uint32_t>(pAddress - sectionData.data());
        rva = (uint32_t)pSection->virtual_address() + offset;
    }
    else if (!YamlGetNumeric(exportDef, "rva", rva))
    {
        fprintf(stderr, "Export entry must have RVA info\n");
        return false;
    }

    if (binary.has_exports())
    {
        pExports = binary.get_export();
    }
    else
    {
        LIEF::PE::Export exportTable;
        binary.set_export(exportTable);
        pExports = binary.get_export();
    }

    if (bNameSpecified)
    {
        printf("Adding export: Name: %.*s RVA: 0x%08" PRIX32 "\n", static_cast<int>(name.length()), name.data(), rva);
        pExports->add_entry(LIEF::PE::ExportEntry(name, rva));
    }
    else
    {
        printf("Adding export: Ordinal: %hu RVA: 0x%08" PRIX32 "\n", ordinal, rva);
        LIEF::PE::ExportEntry exportEntry;
        exportEntry.ordinal(ordinal);
        exportEntry.address(rva);
        pExports->add_entry(exportEntry);
    }

    return true;
}

static bool ProcessExport(LIEF::PE::Binary& binary, const ryml::ConstNodeRef exportDef)
{
    std::string_view op;
    if (!YamlGetStringView(exportDef, "op", op))
    {
        fprintf(stderr, "Export operation has no op\n");
        return false;
    }

    if (op == "add")
    {
        if (!ProcessExportAdd(binary, exportDef))
            return false;
    }
    else
    {
        assert(0);
    }

    return true;
}

static bool ProcessDataPatch(LIEF::PE::Binary& binary, const ryml::ConstNodeRef dataDef)
{
    std::string_view stringPatch;
    std::string_view section;
    uint64_t offset;
    const bool bHasStringPatch = YamlGetStringView(dataDef, "string", stringPatch);

    if (!YamlGetStringView(dataDef, "section", section))
    {
        fprintf(stderr, "Failed to get section name for data patch\n");
        return false;
    }

    if (!YamlGetNumeric(dataDef, "offset", offset))
    {
        fprintf(stderr, "Failed to get offset for data patch\n");
        return false;
    }

    LIEF::PE::Section* pSection = binary.get_section(section);
    if (!pSection)
    {
        fprintf(stderr, "Could not find section %.*s for data patch\n", static_cast<int>(section.length()), section.data());
        return false;
    }

    auto sectionSpan = pSection->writable_content();
    std::vector<uint8_t> bytes;
    if (bHasStringPatch)
    {
        const bool bNullTerminate = YamlGetBool(dataDef, "nullterm", true);

        const size_t nPatchSize = bNullTerminate ? stringPatch.size() + 1 : stringPatch.size();
        if (offset + nPatchSize > sectionSpan.size())
        {
            fprintf(stderr, "Bad offset for section %.*s, section size is %zu offset was %zu\n", static_cast<int>(section.length()), section.data(), pSection->size(), offset);
            return false;
        }

        uint8_t* const pPatchPoint = &sectionSpan[offset];
        std::memcpy(pPatchPoint, stringPatch.data(), stringPatch.size());
        if (bNullTerminate)
        {
            pPatchPoint[stringPatch.size()] = '\0';
        }
    }
    else if (YamlGetBytes(dataDef, "bytes", bytes))
    {    
        uint8_t* pPatchPoint = &sectionSpan[offset];
        std::memcpy(pPatchPoint, bytes.data(), bytes.size());
    }

    return true;
}

static bool UpdateChecksumOnDisk(const std::string& path, uint32_t checksum) {
    std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!file || !file.good()) {
        return false;
    }

    uint32_t e_lfanew = 0;
    file.seekg(0x3C, std::ios::beg);
    file.read(reinterpret_cast<char*>(&e_lfanew), sizeof(e_lfanew));
    if (!file) {
        return false;
    }

    const uint32_t checksum_offset = e_lfanew + 88;

    file.seekp(checksum_offset, std::ios::beg);
    file.write(reinterpret_cast<const char*>(&checksum), sizeof(checksum));
    if (!file) {
        return false;
    }

    return true;
}

static bool ProcessImportsDef(ryml::Tree& tree, LIEF::PE::Binary& pe)
{
    const ryml::ConstNodeRef imports = tree.crootref().find_child("imports");
    
    if (imports.invalid() || (imports.has_val() && imports.val_is_null()))
        return true;

    if (!imports.is_seq()) {
        fprintf(stderr, "Invalid imports block\n");
        return false;
    }

    if (imports.num_children() == 0)
        return true;

    for (const ryml::ConstNodeRef import : imports)
    {
        if (!ProcessImport(pe, import))
            return false;
    }

    return true;
}

static bool ProcessExportsDef(ryml::Tree& tree, LIEF::PE::Binary& pe)
{
    const ryml::ConstNodeRef exports = tree.crootref().find_child("exports");
    if (exports.invalid())
        return true;

    if (!exports.is_map())
        return false;

    if (!YamlGetBool(exports, "clear", false)) {
        if (pe.has_exports())
        {
            LIEF::PE::Export exportTable;
            pe.set_export(exportTable);
        }
    }

    ryml::ConstNodeRef exportEntries = exports.find_child("entries");

    if (exportEntries.invalid() || (exportEntries.has_val() && exportEntries.val_is_null()))
        return true;

    if (!exportEntries.is_seq())
        return false;

    if (exportEntries.num_children() == 0)
        return true;

    for (const ryml::ConstNodeRef exportEntry : exportEntries.children())
    {
        ProcessExport(pe, exportEntry);
    }

    return true;
}

static bool ProcessSymbolsDef(ryml::Tree& tree, CodePatchCtx& patchCtx)
{
    const ryml::ConstNodeRef symbols = tree.crootref().find_child("symbols");
    if (symbols.invalid() || (symbols.has_val() && symbols.val_is_null()))
        return true;
    if (!symbols.is_map())
        return false;
    if (symbols.num_children() == 0)
        return true;

    for (const ryml::ConstNodeRef symbol : symbols.children())
    {
        std::string symbolname(symbol.key().str, symbol.key().len);
        uint64_t val;
        if (!ryml::from_chars(symbol.val(), &val))
        {
            printf("Failed to read symbol %.*s value\n", static_cast<int>(symbolname.length()), symbolname.data());
            return false;
        }

        if (patchCtx.RegisterSymbol(std::move(symbolname), val))
        {
            printf("Adding symbol %.*s value 0x%010" PRIX64 "\n", static_cast<int>(symbol.key().len), symbol.key().str, val);
        }
        else
        {
            printf("Failed to register symbol %.*s\n", static_cast<int>(symbol.key().len), symbol.key().str);
            return false;
        }
    }

    return true;
}

static bool ProcessPatchesDef(ryml::Tree& tree, CodePatchCtx& ctx)
{
    ryml::ConstNodeRef patches = tree.crootref().find_child("patches");

    if (patches.invalid())
        return true;

    if (!patches.is_seq())
        return false;

    if (patches.num_children() == 0)
        return true;

    for (const ryml::ConstNodeRef patch : patches.children())
    {
        std::string_view patchType;
        if (!YamlGetStringView(patch, "type", patchType))
        {
            fprintf(stderr, "Bad patch definition missing / invalid type\n");
            return false;
        }

        if (patchType == "code")
        {
            if (!ctx.SetupCodePatch(patch))
                return false;
        }
        else if (patchType == "data") {
            if (!ProcessDataPatch(ctx.Binary(), patch))
                return false;
        }
    }

    return true;
}

int main(int argc, char** argv) 
{
    if (argc < 2)
        return EXIT_FAILURE;

    std::string inputPath;
    std::string outputPath;
    std::string patchFilePath;

    for (int i = 1; i < argc - 1; i++)
    {
        const char* const pszArg = argv[i];
        if (strcmp(pszArg, "-input") == 0)
        {
            if (i + 1 >= argc)
                return EXIT_FAILURE;

            const char* const pszParam = argv[++i];
            inputPath = pszParam;
        }
        else if (strcmp(pszArg, "-output") == 0) {
            if (i + 1 >= argc)
                return EXIT_FAILURE;
            const char* const pszParam = argv[++i];
            outputPath = pszParam;
        }
        else if (strcmp(pszArg, "-patch") == 0) {
            if (i + 1 >= argc)
                return EXIT_FAILURE;
            const char* const pszParam = argv[++i];
            patchFilePath = pszParam;
        }
        else if (strcmp(pszArg, "--debug") == 0) {
            g_bDebug = true;
        }
        else {
            printf("Unrecognised arg %s\n", pszArg);
            return EXIT_FAILURE;
        }
    }

    if (inputPath.empty() || outputPath.empty() || patchFilePath.empty())
    {
        printf("Input, output and patch file must be specified\n");
        return EXIT_FAILURE;
    }

    if (!std::filesystem::exists(inputPath) || !std::filesystem::is_regular_file(inputPath))
    {
        printf("Bad input file path\n");
        return EXIT_FAILURE;
    }

    std::filesystem::path output(outputPath);
    if (!output.has_filename())
    {
        printf("Bad output file path\n");
        return EXIT_FAILURE;
    }

    if (!std::filesystem::is_directory(output.parent_path()) && !std::filesystem::create_directories(output.parent_path()))
    {
        printf("Could not create directory for output file\n");
        return EXIT_FAILURE;
    }

    if (!std::filesystem::exists(patchFilePath) || !std::filesystem::is_regular_file(patchFilePath))
    {
        printf("Bad patch file path\n");
        return EXIT_FAILURE;
    }

    const std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse(inputPath);
    
    std::ifstream yamlFile = std::ifstream(patchFilePath, std::ios::in | std::ios::binary);
    if (!yamlFile || !yamlFile.good())
    {
        fprintf(stderr, "Failed to open patch yaml\n");
        return EXIT_FAILURE;
    }

    size_t yamlSize = std::filesystem::file_size(patchFilePath);
    char* fileBuffer = new char[yamlSize + 1];
    yamlFile.read(fileBuffer, yamlSize);
    fileBuffer[yamlSize] = '\0';
    ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(fileBuffer));
    delete[] fileBuffer;

    CodePatchCtx patch_context(*pe);

    if (!ProcessImportsDef(tree, *pe))
    {
        return EXIT_FAILURE;
    }

    if (!ProcessExportsDef(tree, *pe))
    {
        return EXIT_FAILURE;
    }

    if (!ProcessSymbolsDef(tree, patch_context))
    {
        return EXIT_FAILURE;
    }

    if (!ProcessPatchesDef(tree, patch_context))
    {
        return EXIT_FAILURE;
    }

    if (!patch_context.ApplyPatches())
    {
        fprintf(stderr, "Failed to apply patches to binary\n");
        return EXIT_FAILURE;
    }

    LIEF::PE::Builder::config_t config;
    config.imports = true;
    config.exports = true;

    pe->optional_header().checksum(0);
    pe->write(outputPath, config);

    uint32_t checksum = 0;

    {
        auto written = LIEF::PE::Parser::parse(outputPath);
        checksum = written->compute_checksum();
    }

    
    UpdateChecksumOnDisk(outputPath, checksum);

    return EXIT_SUCCESS;    
}
