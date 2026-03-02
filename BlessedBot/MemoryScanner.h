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

    // ---- Safe memory access helpers ----
    // SEH (__try/__except) cannot coexist with C++ objects in the same function.
    // These helpers are minimal functions with no C++ objects, so MSVC is happy.

    inline DWORD SafeReadDword(DWORD address, DWORD fallback = 0) {
        __try {
            return *(DWORD*)address;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return fallback;
        }
    }

    inline float SafeReadFloat(DWORD address, float fallback = 0.0f) {
        __try {
            return *(float*)address;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return fallback;
        }
    }

    inline BYTE SafeReadByte(DWORD address, BYTE fallback = 0) {
        __try {
            return *(BYTE*)address;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return fallback;
        }
    }

    inline WORD SafeReadWord(DWORD address, WORD fallback = 0) {
        __try {
            return *(WORD*)address;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return fallback;
        }
    }

    inline bool SafeWriteDword(DWORD address, DWORD value) {
        __try {
            DWORD oldProt;
            VirtualProtect((void*)address, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProt);
            *(DWORD*)address = value;
            VirtualProtect((void*)address, sizeof(DWORD), oldProt, &oldProt);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // Safe string read - copies into a caller-provided buffer (no C++ objects)
    inline int SafeReadStringBuf(DWORD address, char* outBuf, int maxLen) {
        __try {
            int i = 0;
            for (; i < maxLen - 1; i++) {
                char c = *(char*)(address + i);
                if (c == 0) break;
                if (c >= 32 && c <= 126)
                    outBuf[i] = c;
                else
                    break;
            }
            outBuf[i] = 0;
            return i;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            outBuf[0] = 0;
            return 0;
        }
    }

    // ---- C++ wrappers that call the safe helpers ----

    template<typename T>
    inline T ReadMem(DWORD address) {
        // Use IsBadReadPtr as a quick check (no SEH needed here)
        if (IsBadReadPtr((void*)address, sizeof(T)))
            return T{};
        return *(T*)address;
    }

    template<typename T>
    inline bool WriteMem(DWORD address, T value) {
        if (IsBadWritePtr((void*)address, sizeof(T))) {
            DWORD oldProt;
            if (!VirtualProtect((void*)address, sizeof(T), PAGE_EXECUTE_READWRITE, &oldProt))
                return false;
            *(T*)address = value;
            VirtualProtect((void*)address, sizeof(T), oldProt, &oldProt);
            return true;
        }
        *(T*)address = value;
        return true;
    }

    inline std::string ReadString(DWORD address, int maxLen = 32) {
        char buf[256] = {};
        if (maxLen > 255) maxLen = 255;
        SafeReadStringBuf(address, buf, maxLen);
        return std::string(buf);
    }

    // ---- RTTI-based class finder ----
    inline DWORD FindClassInstance(HMODULE hModule, const char* className) {
        char rttiName[256];
        sprintf_s(rttiName, ".?AV%s@@", className);

        DWORD strAddr = Scanner::FindString(hModule, rttiName);
        if (!strAddr) return 0;

        DWORD typeDesc = strAddr - 8;
        auto refs = Scanner::FindXRefs(hModule, typeDesc);

        for (DWORD ref : refs) {
            DWORD potentialVtable = ref + 4;
            auto instances = Scanner::FindXRefs(hModule, potentialVtable);
            if (!instances.empty()) {
                return instances[0];
            }
        }
        return 0;
    }

    // ---- Main scanner ----
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

        DWORD rttiStr = Scanner::FindString(hGame, ".?AVCPlayerMySelf@@");
        if (rttiStr) {
            log << "[FOUND] CPlayerMySelf RTTI at: 0x" << std::hex << rttiStr << "\n";
            auto xrefs = Scanner::FindXRefs(hGame, rttiStr);
            log << "[INFO] Found " << std::dec << xrefs.size() << " xrefs to RTTI\n";
        }
        else {
            log << "[WARN] CPlayerMySelf RTTI not found (may be in packed section)\n";
        }

        DWORD myInfoStr = Scanner::FindString(hGame, "CGameProcMain::MsgRecv_MyInfo_All");
        if (myInfoStr) {
            log << "[FOUND] MsgRecv_MyInfo_All string at: 0x" << std::hex << myInfoStr << "\n";
            auto xrefs = Scanner::FindXRefs(hGame, myInfoStr);
            if (!xrefs.empty()) {
                log << "[INFO] Function reference at: 0x" << std::hex << xrefs[0] << "\n";
            }
        }

        // ---- Find CGameProcMain ----
        log << "\n[SCAN] Searching for CGameProcMain...\n";
        DWORD procMainRtti = Scanner::FindString(hGame, ".?AVCGameProcMain@@");
        if (procMainRtti) {
            log << "[FOUND] CGameProcMain RTTI at: 0x" << std::hex << procMainRtti << "\n";
        }

        // ---- Find send/recv wrappers ----
        log << "\n[SCAN] Searching for packet functions...\n";

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
    inline std::string DumpPlayerMemory(DWORD baseAddr) {
        std::stringstream ss;
        ss << "=== Memory dump around 0x" << std::hex << baseAddr << " ===\n\n";

        for (int offset = 0; offset < 0x200; offset += 4) {
            DWORD val = SafeReadDword(baseAddr + offset);
            float fval = SafeReadFloat(baseAddr + offset);

            ss << "  +0x" << std::hex << offset << ": ";
            ss << "0x" << std::hex << val;

            if (val > 0 && val < 200)
                ss << " (could be level/nation/zone)";
            else if (val > 100 && val < 100000)
                ss << " (could be HP/MP)";
            else if (fval > 0.0f && fval < 10000.0f)
                ss << " (float: " << fval << " - could be coordinate)";

            char strBuf[32] = {};
            if (SafeReadStringBuf(baseAddr + offset, strBuf, 16) > 2)
                ss << " (string: \"" << strBuf << "\")";

            ss << "\n";
        }

        return ss.str();
    }

} // namespace MemScanner
