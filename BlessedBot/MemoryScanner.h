#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <sstream>
#include <vector>
#include "../Common/KOStructs.h"
#include "../Common/PatternScanner.h"

// ============================================================
// Memory Scanner - Find and validate game structures
// Phase 1 tool: scans for player data, validates offsets
// ============================================================

namespace MemScanner {

    struct ScanResult {
        bool success;
        std::string log;

        DWORD pPlayerMySelf;    // CPlayerMySelf base address
        DWORD pGameProcMain;
        DWORD fnSendFunc;       // Game's internal send function
        DWORD fnRecvHandler;    // Game's packet handler

        // Verified offsets
        struct {
            int hp, maxHp, mp, maxMp;
            int posX, posY, posZ;
            int targetId;
            int level, classId, nation;
            int zoneId;
            int name;
        } offsets;
    };

    // Read a value from game memory safely
    template<typename T>
    inline T ReadMem(DWORD address) {
        __try {
            return *(T*)address;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return T{};
        }
    }

    // Write a value to game memory safely
    template<typename T>
    inline bool WriteMem(DWORD address, T value) {
        __try {
            DWORD oldProt;
            VirtualProtect((void*)address, sizeof(T), PAGE_EXECUTE_READWRITE, &oldProt);
            *(T*)address = value;
            VirtualProtect((void*)address, sizeof(T), oldProt, &oldProt);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // Read a string from game memory
    inline std::string ReadString(DWORD address, int maxLen = 32) {
        std::string result;
        __try {
            for (int i = 0; i < maxLen; i++) {
                char c = *(char*)(address + i);
                if (c == 0) break;
                if (c >= 32 && c <= 126) result += c;
                else break;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return result;
    }

    // ---- RTTI-based class finder ----
    // Find CPlayerMySelf instance by locating its RTTI type descriptor
    inline DWORD FindClassInstance(HMODULE hModule, const char* className) {
        // Step 1: Find the RTTI type descriptor string ".?AVClassName@@"
        char rttiName[256];
        sprintf_s(rttiName, ".?AV%s@@", className);

        DWORD strAddr = Scanner::FindString(hModule, rttiName);
        if (!strAddr) return 0;

        // Step 2: The type descriptor is at strAddr - 8 (vtable + spare)
        DWORD typeDesc = strAddr - 8;

        // Step 3: Find references to the type descriptor
        // These lead to the Complete Object Locator, which leads to the vtable
        auto refs = Scanner::FindXRefs(hModule, typeDesc);

        // Step 4: For each reference, look for the vtable pointer
        for (DWORD ref : refs) {
            // The vtable is typically 4 bytes after the COL reference
            // The COL sits just before the vtable in memory
            DWORD potentialVtable = ref + 4;

            // Step 5: Find references to this vtable - these are object instances
            auto instances = Scanner::FindXRefs(hModule, potentialVtable);
            if (!instances.empty()) {
                // Found an instance!
                return instances[0]; // Return the address where vtable pointer is stored
            }
        }

        return 0;
    }

    // ---- Known pattern-based scanner ----
    // These patterns are based on common USKO v23xx builds

    inline ScanResult ScanAll() {
        ScanResult result = {};
        std::stringstream log;

        HMODULE hGame = GetModuleHandleA(nullptr);
        if (!hGame) {
            log << "[FAIL] Could not get game module handle\n";
            result.log = log.str();
            return result;
        }

        log << "[INFO] Game module base: 0x" << std::hex << (DWORD)hGame << "\n";

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hGame;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hGame + dos->e_lfanew);
        DWORD imageSize = nt->OptionalHeader.SizeOfImage;
        log << "[INFO] Image size: 0x" << std::hex << imageSize << "\n";

        // ---- Find CPlayerMySelf ----
        log << "\n[SCAN] Searching for CPlayerMySelf...\n";

        // Method 1: RTTI string search
        DWORD rttiStr = Scanner::FindString(hGame, ".?AVCPlayerMySelf@@");
        if (rttiStr) {
            log << "[FOUND] CPlayerMySelf RTTI at: 0x" << std::hex << rttiStr << "\n";

            // Find xrefs to locate the global pointer
            auto xrefs = Scanner::FindXRefs(hGame, rttiStr);
            log << "[INFO] Found " << std::dec << xrefs.size() << " xrefs to RTTI\n";
        }
        else {
            log << "[WARN] CPlayerMySelf RTTI not found (may be in packed section)\n";
        }

        // Method 2: Pattern scan for known CPlayerMySelf access patterns
        // Common pattern: MOV ECX, [globalPtr] ; CALL CPlayerMySelf::Method
        // In USKO, CPlayerMySelf is often accessed via a global pointer in .data section

        // Scan for "CGameProcMain::MsgRecv_MyInfo_All" which accesses CPlayerMySelf
        DWORD myInfoStr = Scanner::FindString(hGame, "CGameProcMain::MsgRecv_MyInfo_All");
        if (myInfoStr) {
            log << "[FOUND] MsgRecv_MyInfo_All string at: 0x" << std::hex << myInfoStr << "\n";
            auto xrefs = Scanner::FindXRefs(hGame, myInfoStr);
            if (!xrefs.empty()) {
                log << "[INFO] Function reference at: 0x" << std::hex << xrefs[0] << "\n";
                // Near this function, there should be MOV ECX, [CPlayerMySelf_ptr]
            }
        }

        // Method 3: Search data sections for pointer-sized values that could be CPlayerMySelf
        // After the game loads a character, CPlayerMySelf pointer is non-null
        // We can search for it by looking at known patterns

        // ---- Find CGameProcMain ----
        log << "\n[SCAN] Searching for CGameProcMain...\n";
        DWORD procMainRtti = Scanner::FindString(hGame, ".?AVCGameProcMain@@");
        if (procMainRtti) {
            log << "[FOUND] CGameProcMain RTTI at: 0x" << std::hex << procMainRtti << "\n";
        }

        // ---- Find send/recv wrappers ----
        log << "\n[SCAN] Searching for packet functions...\n";

        // The game typically wraps wsock32.send in its own function
        // Pattern: PUSH flags / PUSH len / PUSH buf / PUSH socket / CALL [wsock32.send IAT]
        // IAT address for send: 0xC53610

        DWORD sendIAT = KO::IAT::WS_SEND;
        auto sendRefs = Scanner::FindXRefs(hGame, sendIAT);
        log << "[INFO] Found " << std::dec << sendRefs.size() << " references to send() IAT\n";
        for (size_t i = 0; i < sendRefs.size() && i < 5; i++) {
            log << "  -> 0x" << std::hex << sendRefs[i] << "\n";
        }

        DWORD recvIAT = KO::IAT::WS_RECV;
        auto recvRefs = Scanner::FindXRefs(hGame, recvIAT);
        log << "[INFO] Found " << std::dec << recvRefs.size() << " references to recv() IAT\n";
        for (size_t i = 0; i < recvRefs.size() && i < 5; i++) {
            log << "  -> 0x" << std::hex << recvRefs[i] << "\n";
        }

        // ---- Find DataPack class ----
        log << "\n[SCAN] Searching for DataPack...\n";
        DWORD dataPackRtti = Scanner::FindString(hGame, ".?AVDataPack@@");
        if (dataPackRtti) {
            log << "[FOUND] DataPack RTTI at: 0x" << std::hex << dataPackRtti << "\n";
        }

        // ---- Find skill tables ----
        log << "\n[SCAN] Searching for skill tables...\n";
        const char* skillTables[] = {
            ".?AV?$CN3TableBase@U__TABLE_UPC_SKILL@@@@",
            ".?AV?$CN3TableBase@U__TABLE_UPC_SKILL_TYPE_1@@@@",
            ".?AV?$CN3TableBase@U__TABLE_UPC_SKILL_TYPE_2@@@@"
        };
        for (const char* st : skillTables) {
            DWORD addr = Scanner::FindString(hGame, st);
            if (addr)
                log << "[FOUND] " << st << " at: 0x" << std::hex << addr << "\n";
        }

        // ---- Check KODefender status ----
        log << "\n[SCAN] Checking KODefender...\n";
        HMODULE hDefender = GetModuleHandleA("KODefender.dll");
        if (hDefender) {
            log << "[FOUND] KODefender.dll loaded at: 0x" << std::hex << (DWORD)hDefender << "\n";
        }
        else {
            log << "[INFO] KODefender.dll not loaded\n";
        }

        result.log = log.str();
        result.success = true;
        return result;
    }

    // ---- Live memory dump for debugging ----
    // Dumps player-related memory around a suspected CPlayerMySelf pointer
    inline std::string DumpPlayerMemory(DWORD baseAddr) {
        std::stringstream ss;
        ss << "=== Memory dump around 0x" << std::hex << baseAddr << " ===\n\n";

        for (int offset = 0; offset < 0x200; offset += 4) {
            DWORD val = ReadMem<DWORD>(baseAddr + offset);
            float fval = ReadMem<float>(baseAddr + offset);

            ss << "  +0x" << std::hex << offset << ": ";
            ss << "0x" << std::hex << val;

            // Annotate likely values
            if (val > 0 && val < 200)
                ss << " (could be level/nation/zone)";
            else if (val > 100 && val < 100000)
                ss << " (could be HP/MP)";
            else if (fval > 0.0f && fval < 10000.0f)
                ss << " (float: " << fval << " - could be coordinate)";

            // Check if it's a string
            std::string s = ReadString(baseAddr + offset, 16);
            if (s.length() > 2)
                ss << " (string: \"" << s << "\")";

            ss << "\n";
        }

        return ss.str();
    }

} // namespace MemScanner
