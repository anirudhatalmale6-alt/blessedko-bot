#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <cstdint>

// ============================================================
// Pattern Scanner - Find memory patterns in the KO client
// Supports IDA-style patterns: "48 8B ?? ?? ?? 90"
// ============================================================

namespace Scanner {

    // Parse IDA-style pattern string to bytes + mask
    inline bool ParsePattern(const char* pattern, std::vector<uint8_t>& bytes, std::string& mask) {
        bytes.clear();
        mask.clear();

        const char* p = pattern;
        while (*p) {
            if (*p == ' ') { p++; continue; }
            if (*p == '?') {
                bytes.push_back(0);
                mask += '?';
                p++;
                if (*p == '?') p++; // handle "??"
            }
            else {
                char hex[3] = { p[0], p[1], 0 };
                bytes.push_back((uint8_t)strtoul(hex, nullptr, 16));
                mask += 'x';
                p += 2;
            }
        }
        return !bytes.empty();
    }

    // Scan a memory region for a pattern
    inline DWORD FindPattern(DWORD start, DWORD size, const char* pattern) {
        std::vector<uint8_t> bytes;
        std::string mask;
        if (!ParsePattern(pattern, bytes, mask))
            return 0;

        size_t patLen = bytes.size();
        for (DWORD i = 0; i < size - patLen; i++) {
            bool found = true;
            for (size_t j = 0; j < patLen; j++) {
                if (mask[j] == '?') continue;
                if (*(uint8_t*)(start + i + j) != bytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found)
                return start + i;
        }
        return 0;
    }

    // Scan the main module (.text section typically)
    inline DWORD FindPatternInModule(HMODULE hModule, const char* pattern) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hModule + dos->e_lfanew);

        DWORD base = (DWORD)hModule;
        DWORD size = nt->OptionalHeader.SizeOfImage;

        return FindPattern(base, size, pattern);
    }

    // Get module section info
    struct SectionInfo {
        DWORD start;
        DWORD size;
        char name[9];
    };

    inline std::vector<SectionInfo> GetSections(HMODULE hModule) {
        std::vector<SectionInfo> sections;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hModule + dos->e_lfanew);
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            SectionInfo info;
            info.start = (DWORD)hModule + sec[i].VirtualAddress;
            info.size = sec[i].Misc.VirtualSize;
            memcpy(info.name, sec[i].Name, 8);
            info.name[8] = 0;
            sections.push_back(info);
        }
        return sections;
    }

    // Find RTTI class by name - helps locate vtables and instances
    inline DWORD FindRTTIClass(HMODULE hModule, const char* className) {
        // Build the RTTI type descriptor search string: ".?AVClassName@@"
        char rtti[256];
        sprintf_s(rtti, ".?AV%s@@", className);

        return FindPatternInModule(hModule, nullptr); // placeholder - need string search
    }

    // String search in module
    inline DWORD FindString(HMODULE hModule, const char* str) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hModule + dos->e_lfanew);

        DWORD base = (DWORD)hModule;
        DWORD size = nt->OptionalHeader.SizeOfImage;
        size_t len = strlen(str);

        for (DWORD i = 0; i < size - len; i++) {
            if (memcmp((void*)(base + i), str, len) == 0)
                return base + i;
        }
        return 0;
    }

    // Find all references (xrefs) to an address within the module
    inline std::vector<DWORD> FindXRefs(HMODULE hModule, DWORD targetAddr) {
        std::vector<DWORD> refs;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hModule + dos->e_lfanew);

        DWORD base = (DWORD)hModule;
        DWORD size = nt->OptionalHeader.SizeOfImage;

        // Look for PUSH addr, MOV reg, addr, or LEA patterns
        for (DWORD i = 0; i < size - 4; i++) {
            DWORD val = *(DWORD*)(base + i);
            if (val == targetAddr) {
                refs.push_back(base + i);
            }
        }
        return refs;
    }

} // namespace Scanner
