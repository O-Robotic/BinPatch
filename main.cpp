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

#include "thirdparty/yaml-cpp/include/yaml-cpp/yaml.h"
#include <regex>

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
    uint64_t m_nOffsetInCaveSection = 0;
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
    explicit CodePatchCtx(LIEF::PE::Binary& bin) : binary(bin) {
    }

    bool SetupCodePatch(const YAML::Node& patchJson)
    {
        const std::string_view segmentName = patchJson["segment"].as<std::string_view>();
        const std::string patchASM = patchJson["patch"].as<std::string>();
        const std::string_view mode = patchJson["mode"].as<std::string_view>();

        LIEF::PE::Section* section = nullptr;
        for (auto& sectionItr : binary.sections()) {
            if (sectionItr.name() == segmentName) {
                section = &sectionItr;
                break;
            }
        }

        if (!section) {
            std::cout << "Could not find section " << segmentName << std::endl;
            return false;
        }

        auto sectionData = section->writable_content();

        const uint8_t* pPatchAddress = nullptr;
        if (patchJson["sig"]) {
            const std::string_view sig = patchJson["sig"].as<std::string_view>();
            const auto [bytes, mask] = PatternToMaskedBytes(sig);
            pPatchAddress = FindPattern(sectionData, bytes, mask);

            if (!pPatchAddress)
            {
                std::cout << std::format("Could not find pattern [{}] in segment {}", sig, segmentName) << std::endl;
                return false;
            }
            else
            {
                std::cout << std::format("Building code patch for [{}]", sig) << std::endl;
            }
        }

        if (!pPatchAddress) {
            return false;
        }

        const uint64_t offset = static_cast<uint64_t>(pPatchAddress - sectionData.data());
        const uint64_t patchVA = binary.imagebase() + section->virtual_address() + offset;
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
            bool bJumpBack = true;
            bool bKeepStolen = true;
            StolenByteRestorePos byteRestorePos = StolenByteRestorePos::Leading;

            if (patchJson["jump_back"])
            {
                bJumpBack = patchJson["jump_back"].as<bool>();
            }

            if (patchJson["keep_stolen"])
            {
                bKeepStolen = patchJson["keep_stolen"].as<bool>();
            }

            if (patchJson["byte_restore_pos"])
            {
                const std::string_view restorePosStr = patchJson["byte_restore_pos"].as<std::string_view>();
                if (restorePosStr == "trailing")
                    byteRestorePos = StolenByteRestorePos::Trailing;
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

        const std::optional<std::vector<uint8_t>> assembledRes = assembler.Assemble(pszPatchASM, patchVA);
        if (!assembledRes)
            return false;

        const std::vector<uint8_t>& assembled = *assembledRes;

        if (g_bDebug)
        {
            const std::string printed = disassembler.PrintInstructions(assembled, patchVA);
            std::cout << printed << std::endl;
        }
       
        const size_t window = std::min<size_t>(assembled.size() + 16, sectionRemaining);
        const std::span<const uint8_t> patchableBytes = { pPatchAddress, window };

        const std::optional<size_t> result = disassembler.GetStolenByteCount(patchableBytes, assembled.size());
        
        if (!result)
            return false;

        patch.m_nPatchVA = patchVA;
        patch.m_PatchBytes.assign(*result, 0x90);
        memcpy(patch.m_PatchBytes.data(), assembled.data(), assembled.size());

        patches.push_back(patch);
        return true;
    }

    bool SetupTrampolinePatch(std::string patchASM, const uint8_t* pPatchAddress,
        uint64_t patchVA, size_t sectionRemaining, bool bJumpBack, bool bKeepStolenInstructions, StolenByteRestorePos restorePos)
    {
        TrampolinePatch tp;
        tp.m_PatchASM = std::move(patchASM);

        const std::optional<std::vector<uint8_t>> assembledRes = assembler.Assemble(tp.m_PatchASM.c_str(), patchVA);

        if (!assembledRes)
            return false;

        const std::vector<uint8_t>& assembled = *assembledRes;

        const size_t window = std::min<size_t>(5 + 16, sectionRemaining);
        const std::span<const uint8_t> patchableBytes = { pPatchAddress, window };

        const std::optional<size_t> res = disassembler.GetStolenByteCount(patchableBytes, 5);
        if (!res)
            return false;

        std::vector<uint8_t> stolenBytesVec(pPatchAddress, pPatchAddress + *res);

        size_t reloactedSize = 0;
        if (bKeepStolenInstructions)
        {
            const std::vector<uint8_t> relocated = disassembler.RelocateInstructions(stolenBytesVec, patchVA, patchVA + 16);
            reloactedSize = relocated.size();
        }

        const size_t caveSize = reloactedSize + assembled.size() + 5;
        const size_t alignedOffset = (lastCaveOffset + 15) & ~size_t(15);

        tp.m_nPatchVA = patchVA;
        tp.m_StolenBytes = std::move(stolenBytesVec);
        tp.m_nOffsetInCaveSection = alignedOffset;
        tp.m_nCaveSize = caveSize;
        tp.m_bJumpBack = bJumpBack;
        tp.m_bKeepStolenInstructions = bKeepStolenInstructions;
        tp.m_RestorePos = restorePos;

        lastCaveOffset = alignedOffset + caveSize;
        trampolinePatches.push_back(tp);
        return true;
    }

    inline LIEF::PE::Binary& Binary() { return binary; }

    bool ApplyInlinePatches() const
    {
        for (auto& patch : patches)
        {
            binary.patch_address(patch.m_nPatchVA, patch.m_PatchBytes, LIEF::Binary::VA_TYPES::VA);
        }

        return true;
    }

    bool ApplyTrampolinePatches() const
    {
        const size_t totalCaveSize = trampolinePatches.empty() ? 0
            : trampolinePatches.back().m_nOffsetInCaveSection + trampolinePatches.back().m_nCaveSize;

        if (totalCaveSize == 0)
            return true;

        LIEF::PE::Section* caveSection = AllocateCaveSection(binary, totalCaveSize);
        const uint64_t caveBaseVA = binary.imagebase() + caveSection->virtual_address();

        for (auto& patch : trampolinePatches)
        {
            const uint64_t caveVA = caveBaseVA + patch.m_nOffsetInCaveSection;

            std::vector<uint8_t> body;

            if (patch.m_RestorePos == StolenByteRestorePos::Leading)
            {
                std::vector<uint8_t> relocated;

                if (patch.m_bKeepStolenInstructions)
                {
                    relocated = disassembler.RelocateInstructions(patch.m_StolenBytes, patch.m_nPatchVA, caveVA);
                }

                const uint64_t injectedVA = caveVA + relocated.size();
                const std::optional<std::vector<uint8_t>> assembledRes = assembler.Assemble(patch.m_PatchASM.c_str(), injectedVA);
                if (!assembledRes)
                    return false;

                body = std::move(relocated);
                body.insert(body.end(), assembledRes->begin(), assembledRes->end());
            }
            else
            {
                const std::optional<std::vector<uint8_t>> injectedRes = assembler.Assemble(patch.m_PatchASM.c_str(), caveVA);
                const uint64_t relocatedVA = caveVA + injectedRes->size();

                std::vector<uint8_t> relocated;
                if (patch.m_bKeepStolenInstructions)
                {
                    relocated = disassembler.RelocateInstructions(patch.m_StolenBytes, patch.m_nPatchVA, relocatedVA);

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
                std::memcpy(relBytes, &rel, 4);
                body.insert(body.end(), relBytes, relBytes + sizeof(relBytes));
            }

            binary.patch_address(caveVA, body);

            std::vector<uint8_t> jumpOut(patch.m_StolenBytes.size(), 0x90);
            jumpOut[0] = 0xE9;
            const int32_t outRel = static_cast<int32_t>(caveVA - (patch.m_nPatchVA + 5));
            memcpy(&jumpOut[1], &outRel, sizeof(outRel));
            binary.patch_address(patch.m_nPatchVA, jumpOut);
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

private:
    LIEF::PE::Binary& binary;
    std::vector<CodePatch> patches;
    std::vector<TrampolinePatch> trampolinePatches;
    Disassembler disassembler;
    Assembler assembler;
    uint64_t lastCaveOffset = 0;
};

static void AddImportEntry(LIEF::PE::Import& import_, const YAML::Node& entry)
{
    const bool bHasOrdinal = entry.contains("ordinal");
    const bool bHasName = entry.contains("name");

    if (bHasOrdinal == bHasName)
    {
        fprintf(stderr, "Import definition must have either a name or ordinal\n");
        return;
    }

    if (bHasOrdinal)
    {
        const uint32_t ordinal = entry["ordinal"].as<uint32_t>();

        if (ordinal < 1 || ordinal > UINT16_MAX)
        {
            fprintf(stderr, "Invalid ordinal specified for entry %" PRIu32 "\n", ordinal);
            return;
        }

        printf("Adding import entry with ordinal %" PRIu32 "\n", ordinal);
        LIEF::PE::ImportEntry importEntry((1ull << 63) | ordinal, LIEF::PE::PE_TYPE::PE32_PLUS);
        import_.add_entry(importEntry);
    }
    else
    {
        const std::string name = entry["name"].as<std::string>();
        if (name.empty())
        {
            fprintf(stderr, "Empty name specified for entry\n");
            return;
        }

        printf("Adding import entry with name %s\n", name.c_str());
        import_.add_entry(name);
    }
}

static void RemoveImportEntry(LIEF::PE::Import& import_, const YAML::Node& entry)
{
    const bool bHasOrdinal = entry.contains("ordinal");
    const bool bHasName = entry.contains("name");

    if (bHasOrdinal == bHasName)
    {
        fprintf(stderr, "Import definition must have either a name or ordinal\n");
        return;
    }

    if (bHasOrdinal)
    {
        const uint32_t ordinal = entry["ordinal"].as<uint32_t>();

        if (ordinal < 1 || ordinal > UINT16_MAX)
        {
            fprintf(stderr, "Invalid ordinal specified for entry %" PRIu32 "\n", ordinal);
            return;
        }

        if (import_.remove_entry(ordinal))
        {
            printf("Removed import entry with ordinal %" PRIu32 "\n", ordinal);
        }
        else
        {
            printf("Failed to remove import entry with ordinal %" PRIu32 "\n", ordinal);
        }
    }
    else
    {
        const std::string name = entry["name"].as<std::string>();

        if (name.empty())
        {
            fprintf(stderr, "Empty name specified for entry\n");
            return;
        }

        if (import_.remove_entry(name))
        {
            printf("Removed import entry with name %s\n", name.c_str());
        }
        else
        {
            printf("Failed to remove import entry with name %s\n", name.c_str());
        }
    }
}

static void ProcessImportAdd(LIEF::PE::Binary& binary, const YAML::Node& importDef)
{
    if (!importDef.contains("module"))
    {
        fprintf(stderr, "No module specified for adding an import\n");
        return;
    }

    if (!importDef.contains("entries") && importDef["entries"].IsSequence())
    {
        fprintf(stderr, "Import definition must have at least one entry\n");
        return;
    }

    const std::string module_name = importDef["module"].as<std::string>();
    printf("Adding import %s\n", module_name.c_str());
    LIEF::PE::Import& new_import = binary.add_import(module_name);

    for (const auto& entry : importDef["entries"])
    {
        AddImportEntry(new_import, entry);
    }
}

static void ProcessImportEdit(LIEF::PE::Binary& binary, const YAML::Node& importDef)
{
    if (!importDef.contains("module"))
    {
        fprintf(stderr, "No module specified for modifying an import\n");
        return;
    }

    if (importDef.contains("remove") && importDef["remove"].as<bool>())
    {
        binary.remove_import(importDef["module"].as<std::string>());
        return;
    }

    const std::string moduleName = importDef["module"].as<std::string>();
    LIEF::PE::Import* pImport = binary.get_import(moduleName);

    if (!pImport)
    {
        fprintf(stderr, "No import exists for module %s\n", moduleName.c_str());
        return;
    }

    if (!importDef.contains("entries"))
    {
        fprintf(stderr, "Import modification must have at least one entry\n");
        return;
    }

    for (const auto& entry : importDef["entries"])
    {
        if (!entry.contains("op"))
        {
            fprintf(stderr, "Import entry modification specified with no op\n");
            continue;
        }

        std::string_view op = entry["op"].as<std::string_view>();

        if (op == "add")
        {
            AddImportEntry(*pImport, entry);
        }
        else if (op == "remove")
        {
            RemoveImportEntry(*pImport, entry);
        }
        else
        {
            assert(0);
        }
    }
}

static void ProcessImport(LIEF::PE::Binary& binary, const YAML::Node& importDef)
{
    if (!importDef.contains("mode"))
    {
        fprintf(stderr, "Import operation has no mode\n");
        return;
    }

    std::string_view mode = importDef["mode"].as<std::string_view>();

    if (mode == "add")
    {
        ProcessImportAdd(binary, importDef);
    }
    else if(mode == "edit")
    {
        ProcessImportEdit(binary, importDef);
    }
    else
    {
        assert(0);
    }
}

static void ProcessExportAdd(LIEF::PE::Binary& binary, const YAML::Node& exportDef)
{
    const bool bOrdinalSpecified = exportDef.contains("ordinal");
    const bool bNameSpecified = exportDef.contains("name");

    if (bOrdinalSpecified == bNameSpecified)
    {
        fprintf(stderr, "Export add must have either a name or ordinal\n");
        return;
    }

    LIEF::PE::Export* pExports;

    uint32_t rva = 0;

    if (exportDef.contains("rva"))
    {
        rva = exportDef["rva"].as<uint32_t>();
    }
    else if (exportDef.contains("rva_sig"))
    {
        const YAML::Node& rva_sig_node = exportDef["rva_sig"];
        const std::string sectionName = rva_sig_node["section"].as<std::string>();
        const std::string_view sigString = rva_sig_node["sig"].as<std::string_view>();

        if (sectionName.empty() || sigString.empty())
        {
            fprintf(stderr, "Bad rva_sig definition for export\n");
            return;
        }

        LIEF::PE::Section* pSection = binary.get_section(sectionName);
        if (!pSection)
        {
            fprintf(stderr, "Section specified in rva_sig definition for export not found\n");
            return;
        }

        std::span<const uint8_t> sectionData = pSection->writable_content();
                
        const auto [bytes, mask] = PatternToMaskedBytes(sigString);
        const uint8_t* pAddress = FindPattern(sectionData, bytes, mask);
        
        const uint32_t offset = static_cast<uint32_t>(pAddress - sectionData.data());
        rva = (uint32_t)pSection->virtual_address() + offset;
    }
    else
    {
        fprintf(stderr, "Export entry must have RVA info\n");
        return;
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
        std::string exportName = exportDef["name"].as<std::string>();
        printf("Adding export: Name: %s RVA: 0x%10" PRIX32 "\n", exportName.c_str(), rva);
        pExports->add_entry(LIEF::PE::ExportEntry(exportName, rva));
    }
    else
    {
        uint16_t ordinal = exportDef["ordinal"].as<uint16_t>();
        printf("Adding export: Ordinal: %hu RVA: 0x%10" PRIX32 "\n", ordinal, rva);
        LIEF::PE::ExportEntry exportEntry;
        exportEntry.ordinal(ordinal);
        exportEntry.address(rva);
        pExports->add_entry(exportEntry);
    }
}

static void ProcessExport(LIEF::PE::Binary& binary, const YAML::Node& exportDef)
{
    if (!exportDef.contains("op"))
    {
        fprintf(stderr, "Export operation has no op\n");
        return;
    }

    std::string_view op = exportDef["op"].as<std::string_view>();

    if (op == "add")
    {
        ProcessExportAdd(binary, exportDef);
    }
    else
    {
        assert(0);
    }
}

static void ProcessDataPatch(LIEF::PE::Binary& binary, const YAML::Node& dataDef)
{
    const bool bHasStringPatch = dataDef.contains("string");
    std::string section = dataDef["section"].as<std::string>();
    size_t offset = dataDef["offset"].as<size_t>();

    LIEF::PE::Section* pSection = binary.get_section(section);
    if (!pSection)
    {
        fprintf(stderr, "Could not find section %s for data patch\n", section.c_str());
        return;
    }

    auto sectionSpan = pSection->writable_content();

    if (bHasStringPatch)
    {
        bool bNullTerminate = true;
        if (dataDef.contains("nullterm") && !dataDef["nullterm"].as<bool>())
        {
            bNullTerminate = false;
        }

        const std::string newString = dataDef["string"].as<std::string>();
        const size_t nBytesToCopy = bNullTerminate ? newString.size() + 1 : newString.size();

        if (offset + nBytesToCopy > sectionSpan.size())
        {
            fprintf(stderr, "Bad offset for section %s, section size is %zu offset was %zu\n", section.c_str(), section.size(), offset);
            return;
        }

        uint8_t* const pPatchPoint = &sectionSpan[offset];
        std::memcpy(pPatchPoint, newString.c_str(), nBytesToCopy);
    }
    else if (dataDef["bytes"])
    {
        std::vector<uint8_t> data = dataDef["bytes"].as<std::vector<uint8_t>>();
    
        uint8_t* pPatchPoint = &sectionSpan[offset];
        std::memcpy(pPatchPoint, data.data(), data.size());
    }
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
    const YAML::Node patchFile = YAML::LoadFile(patchFilePath);

    if (!patchFile["patches"] || !patchFile["patches"].IsSequence())
    {
        fprintf(stderr, "Invalid patch file, missing patch sequence\n");
        return EXIT_FAILURE;
    }

    const YAML::Node patches = patchFile["patches"];

    CodePatchCtx patch_context(*pe);

    if (patchFile.contains("imports") && patchFile["imports"].IsSequence())
    {
        for (const auto& import : patchFile["imports"])
        {
            ProcessImport(*pe, import);
        }
    }

    if (patchFile.contains("exports") && patchFile["exports"].IsMap())
    {
        const YAML::Node& exports = patchFile["exports"];

        if (exports["clear"])
        {
            if (pe->has_exports())
            {
                LIEF::PE::Export exportTable;
                pe->set_export(exportTable);
            }
        }

        for (const auto& export_ : exports["entries"])
        {
            ProcessExport(*pe, export_);
        }
    }

    bool bPatchSuccessful = true; 

    for (auto& patch : patches) {
        
        const std::string_view patchOp = patch["type"].as<std::string_view>();

        if (patchOp == "code") {
            if (!patch_context.SetupCodePatch(patch))
            {
                bPatchSuccessful = false;
                printf("Code patch failed\n");
                break;
            }
        }
        else if (patchOp == "data") {
            ProcessDataPatch(*pe, patch);
        }
    }
    
    if (!bPatchSuccessful)
        return EXIT_FAILURE;

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
