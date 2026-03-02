#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <mutex>
#include <functional>
#include <cstdio>
#include "../Common/KOStructs.h"

// ============================================================
// Hooks v4 - Hot-Patch Hooking
//
// Both wsock32.send and recv have Microsoft hot-patch prologues:
//   [5 bytes CC/90 padding] [8B FF = MOV EDI,EDI] [55 = PUSH EBP] ...
//
// Hot-patch technique:
// 1. Write JMP rel32 to our hook in the 5-byte padding BEFORE the function
// 2. Replace MOV EDI,EDI (8B FF) with JMP SHORT -5 (EB F9) at func start
// 3. Trampoline = MOV EDI,EDI (8B FF) + JMP to funcAddr+2
//
// Key insight from debug log:
// - wsock32.send IS ws2_32.send (forwarded export, same address 0x76796C30)
// - wsock32.recv is its own function at 0x73581560
// - Both start with 8B FF 55 8B EC = hot-patch prologue
//
// This means we can't use "call ws2_32.send as original" for send,
// because it's the SAME function we're hooking. Hot-patch solves this
// cleanly with a 7-byte trampoline.
// ============================================================

namespace Hooks {

    typedef int (WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WINAPI* tRecv)(SOCKET s, char* buf, int len, int flags);

    // Original function trampolines (tiny: MOV EDI,EDI + JMP back)
    inline tSend oSend = nullptr;
    inline tRecv oRecv = nullptr;

    inline SOCKET gameSocket = INVALID_SOCKET;

    // Hooked function addresses
    inline DWORD sendFuncAddr = 0;
    inline DWORD recvFuncAddr = 0;

    // Original bytes for unhooking
    inline uint8_t sendOrigPad[5] = {};   // 5 bytes before function
    inline uint8_t sendOrigHead[2] = {};  // 2 bytes at function start (8B FF)
    inline uint8_t recvOrigPad[5] = {};
    inline uint8_t recvOrigHead[2] = {};

    // Trampolines (allocated executable memory)
    inline uint8_t* sendTrampoline = nullptr;
    inline uint8_t* recvTrampoline = nullptr;

    // Debug
    inline FILE* logFile = nullptr;
    inline char debugInfo[2048] = {};
    inline int debugPos = 0;

    inline void LogToFile(const char* fmt, ...) {
        if (!logFile) fopen_s(&logFile, "BlessedBot_debug.log", "a");
        if (logFile) {
            va_list args;
            va_start(args, fmt);
            vfprintf(logFile, fmt, args);
            va_end(args);
            fflush(logFile);
        }
    }

    inline void DbgLog(const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        int written = vsnprintf(debugInfo + debugPos, sizeof(debugInfo) - debugPos, fmt, args);
        va_end(args);
        if (written > 0) debugPos += written;
        va_start(args, fmt);
        LogToFile("[HOOK] ");
        if (logFile) { vfprintf(logFile, fmt, args); fflush(logFile); }
        va_end(args);
    }

    // Packet log
    struct PacketLog {
        bool     isSend;
        DWORD    timestamp;
        std::vector<uint8_t> data;
    };

    inline std::vector<PacketLog> packetLog;
    inline std::mutex logMutex;
    constexpr size_t MAX_LOG_SIZE = 1000;

    using PacketCallback = std::function<bool(bool isSend, const uint8_t* data, int len)>;
    inline PacketCallback onPacket = nullptr;

    inline int SendGamePacket(const uint8_t* data, int len) {
        if (oSend && gameSocket != INVALID_SOCKET)
            return oSend(gameSocket, (const char*)data, len, 0);
        return -1;
    }

    // ---- Hook implementations ----
    __declspec(noinline) static int WINAPI hkSendImpl(SOCKET s, const char* buf, int len, int flags) {
        if (gameSocket == INVALID_SOCKET)
            gameSocket = s;

        {
            std::lock_guard<std::mutex> lock(logMutex);
            PacketLog entry;
            entry.isSend = true;
            entry.timestamp = GetTickCount();
            if (len > 0 && buf)
                entry.data.assign((uint8_t*)buf, (uint8_t*)buf + len);
            packetLog.push_back(entry);
            if (packetLog.size() > MAX_LOG_SIZE)
                packetLog.erase(packetLog.begin());
        }

        if (onPacket) {
            bool allow = onPacket(true, (const uint8_t*)buf, len);
            if (!allow) return len;
        }

        // Call original via trampoline (MOV EDI,EDI + JMP to func+2)
        return oSend(s, buf, len, flags);
    }

    __declspec(noinline) static int WINAPI hkRecvImpl(SOCKET s, char* buf, int len, int flags) {
        int result = oRecv(s, buf, len, flags);

        if (result > 0) {
            {
                std::lock_guard<std::mutex> lock(logMutex);
                PacketLog entry;
                entry.isSend = false;
                entry.timestamp = GetTickCount();
                entry.data.assign((uint8_t*)buf, (uint8_t*)buf + result);
                packetLog.push_back(entry);
                if (packetLog.size() > MAX_LOG_SIZE)
                    packetLog.erase(packetLog.begin());
            }

            if (onPacket) {
                onPacket(false, (const uint8_t*)buf, result);
            }
        }

        return result;
    }

    // ---- Hex dump helper ----
    inline void HexDump(DWORD addr, int count, char* out, int outSize) {
        int pos = 0;
        for (int i = 0; i < count && pos < outSize - 4; i++)
            pos += sprintf_s(out + pos, outSize - pos, "%02X ", *(uint8_t*)(addr + i));
    }

    // ---- Create hot-patch trampoline ----
    // Just 7 bytes: MOV EDI,EDI (8B FF) + JMP rel32 to funcAddr+2
    inline uint8_t* CreateHotPatchTrampoline(DWORD funcAddr) {
        uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, 16,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tramp) return nullptr;

        // MOV EDI, EDI (the original 2-byte instruction we're replacing)
        tramp[0] = 0x8B;
        tramp[1] = 0xFF;

        // JMP to funcAddr + 2 (skip past the MOV EDI,EDI we replaced with JMP SHORT)
        tramp[2] = 0xE9;
        DWORD jmpTarget = funcAddr + 2;
        *(int32_t*)(tramp + 3) = (int32_t)(jmpTarget - (DWORD)(tramp + 7));

        return tramp;
    }

    // ---- Apply hot-patch hook ----
    // funcAddr must point to 8B FF (MOV EDI,EDI) with 5 bytes of padding before it
    inline bool ApplyHotPatch(DWORD funcAddr, DWORD hookAddr,
        uint8_t* backupPad, uint8_t* backupHead, const char* name) {

        uint8_t* pFunc = (uint8_t*)funcAddr;

        // Verify hot-patch prologue
        if (pFunc[0] != 0x8B || pFunc[1] != 0xFF) {
            DbgLog("%s: NOT hot-patchable (bytes: %02X %02X, expected 8B FF)\n",
                name, pFunc[0], pFunc[1]);
            return false;
        }

        // Check the 5 bytes before the function (should be CC or 90 padding)
        uint8_t* pPad = pFunc - 5;
        bool padOk = true;
        for (int i = 0; i < 5; i++) {
            if (pPad[i] != 0xCC && pPad[i] != 0x90 && pPad[i] != 0x00) {
                padOk = false;
                break;
            }
        }

        char hexBuf[32];
        HexDump((DWORD)pPad, 5, hexBuf, sizeof(hexBuf));
        DbgLog("%s: padding bytes [-5]: %s (%s)\n", name, hexBuf, padOk ? "OK" : "NOT standard padding");

        if (!padOk) {
            DbgLog("%s: WARNING - padding not standard, but proceeding anyway\n", name);
        }

        // Backup original bytes
        memcpy(backupPad, pPad, 5);
        memcpy(backupHead, pFunc, 2);

        // Step 1: Write JMP rel32 to our hook in the 5-byte padding area
        DWORD oldProt;
        if (!VirtualProtect(pPad, 7, PAGE_EXECUTE_READWRITE, &oldProt)) {
            DbgLog("%s: VirtualProtect failed: %d\n", name, GetLastError());
            return false;
        }

        // JMP rel32 at funcAddr-5
        pPad[0] = 0xE9;
        *(int32_t*)(pPad + 1) = (int32_t)(hookAddr - (DWORD)(pPad + 5));

        // Step 2: Replace MOV EDI,EDI with JMP SHORT -5 (jumps to the JMP we just wrote)
        pFunc[0] = 0xEB;  // JMP SHORT
        pFunc[1] = 0xF9;  // -7 (relative to next instruction at pFunc+2, target = pFunc+2-7 = pFunc-5)

        VirtualProtect(pPad, 7, oldProt, &oldProt);

        // Verify
        HexDump((DWORD)pPad, 7, hexBuf, sizeof(hexBuf));
        DbgLog("%s: patched [-5..+2]: %s\n", name, hexBuf);

        return true;
    }

    // ---- Restore hot-patch ----
    inline bool RestoreHotPatch(DWORD funcAddr, uint8_t* backupPad, uint8_t* backupHead) {
        uint8_t* pFunc = (uint8_t*)funcAddr;
        uint8_t* pPad = pFunc - 5;

        DWORD oldProt;
        if (!VirtualProtect(pPad, 7, PAGE_EXECUTE_READWRITE, &oldProt))
            return false;

        memcpy(pPad, backupPad, 5);
        memcpy(pFunc, backupHead, 2);

        VirtualProtect(pPad, 7, oldProt, &oldProt);
        return true;
    }

    // ---- Install Hooks ----
    inline bool InstallNetworkHooks() {
        debugPos = 0;
        memset(debugInfo, 0, sizeof(debugInfo));

        DbgLog("=== Hook Install v4 (Hot-Patch) ===\n");

        // Get module handles
        HMODULE hWsock = GetModuleHandleA("wsock32.dll");
        if (!hWsock) hWsock = LoadLibraryA("wsock32.dll");
        HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
        if (!hWs2) hWs2 = LoadLibraryA("ws2_32.dll");

        if (!hWsock) { DbgLog("FAIL: wsock32.dll not found\n"); return false; }

        DbgLog("wsock32.dll at: 0x%08X\n", (DWORD)hWsock);
        DbgLog("ws2_32.dll at: 0x%08X\n", (DWORD)hWs2);

        // Get export addresses
        DWORD wsockSend = (DWORD)GetProcAddress(hWsock, "send");
        DWORD wsockRecv = (DWORD)GetProcAddress(hWsock, "recv");
        DWORD ws2Send = hWs2 ? (DWORD)GetProcAddress(hWs2, "send") : 0;
        DWORD ws2Recv = hWs2 ? (DWORD)GetProcAddress(hWs2, "recv") : 0;

        char hexBuf[128];

        HexDump(wsockSend, 16, hexBuf, sizeof(hexBuf));
        DbgLog("wsock32.send (0x%08X): %s\n", wsockSend, hexBuf);
        HexDump(wsockRecv, 16, hexBuf, sizeof(hexBuf));
        DbgLog("wsock32.recv (0x%08X): %s\n", wsockRecv, hexBuf);

        if (ws2Send) {
            HexDump(ws2Send, 16, hexBuf, sizeof(hexBuf));
            DbgLog("ws2_32.send (0x%08X): %s\n", ws2Send, hexBuf);
        }
        if (ws2Recv) {
            HexDump(ws2Recv, 16, hexBuf, sizeof(hexBuf));
            DbgLog("ws2_32.recv (0x%08X): %s\n", ws2Recv, hexBuf);
        }

        DbgLog("wsock32.send == ws2_32.send? %s\n", wsockSend == ws2Send ? "YES (forwarded)" : "NO");
        DbgLog("wsock32.recv == ws2_32.recv? %s\n", wsockRecv == ws2Recv ? "YES (forwarded)" : "NO");

        // Determine which addresses to hook
        // For send: wsock32.send IS ws2_32.send (forwarded export), hook at that address
        // For recv: wsock32.recv is different, hook wsock32.recv
        // (game calls wsock32, so we hook what the game actually calls)
        sendFuncAddr = wsockSend;
        recvFuncAddr = wsockRecv;

        DbgLog("\nHooking send at: 0x%08X\n", sendFuncAddr);
        DbgLog("Hooking recv at: 0x%08X\n", recvFuncAddr);

        // Create trampolines (MOV EDI,EDI + JMP to func+2)
        sendTrampoline = CreateHotPatchTrampoline(sendFuncAddr);
        recvTrampoline = CreateHotPatchTrampoline(recvFuncAddr);

        if (!sendTrampoline || !recvTrampoline) {
            DbgLog("FAIL: Could not allocate trampolines\n");
            return false;
        }

        oSend = (tSend)sendTrampoline;
        oRecv = (tRecv)recvTrampoline;

        DbgLog("send trampoline at: 0x%08X\n", (DWORD)sendTrampoline);
        DbgLog("recv trampoline at: 0x%08X\n", (DWORD)recvTrampoline);

        // Verify trampolines
        HexDump((DWORD)sendTrampoline, 7, hexBuf, sizeof(hexBuf));
        DbgLog("send trampoline bytes: %s\n", hexBuf);
        HexDump((DWORD)recvTrampoline, 7, hexBuf, sizeof(hexBuf));
        DbgLog("recv trampoline bytes: %s\n", hexBuf);

        // Get hook function addresses
        DWORD hookSendAddr = (DWORD)&hkSendImpl;
        DWORD hookRecvAddr = (DWORD)&hkRecvImpl;
        DbgLog("hkSendImpl at: 0x%08X\n", hookSendAddr);
        DbgLog("hkRecvImpl at: 0x%08X\n", hookRecvAddr);

        // Apply hot-patches
        DbgLog("\nApplying hot-patches...\n");

        bool sendOk = ApplyHotPatch(sendFuncAddr, hookSendAddr, sendOrigPad, sendOrigHead, "send");
        bool recvOk = ApplyHotPatch(recvFuncAddr, hookRecvAddr, recvOrigPad, recvOrigHead, "recv");

        DbgLog("\nResult: send=%s recv=%s\n", sendOk ? "OK" : "FAIL", recvOk ? "OK" : "FAIL");
        DbgLog("=== Hook Install Complete ===\n");

        return sendOk && recvOk;
    }

    // ---- Remove Hooks ----
    inline void RemoveNetworkHooks() {
        if (sendFuncAddr)
            RestoreHotPatch(sendFuncAddr, sendOrigPad, sendOrigHead);
        if (recvFuncAddr)
            RestoreHotPatch(recvFuncAddr, recvOrigPad, recvOrigHead);
        if (sendTrampoline) { VirtualFree(sendTrampoline, 0, MEM_RELEASE); sendTrampoline = nullptr; }
        if (recvTrampoline) { VirtualFree(recvTrampoline, 0, MEM_RELEASE); recvTrampoline = nullptr; }
        oSend = nullptr;
        oRecv = nullptr;
        if (logFile) { fclose(logFile); logFile = nullptr; }
    }

    // ---- IAT Hook Helper (for DefenderBypass) ----
    inline bool PatchIAT(HMODULE hModule, const char* dllName, const char* funcName, DWORD newFunc, DWORD* oldFunc) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hModule + dos->e_lfanew);
        PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)(
            (DWORD)hModule + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        for (; imports->Name; imports++) {
            const char* name = (const char*)((DWORD)hModule + imports->Name);
            if (_stricmp(name, dllName) != 0) continue;

            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((DWORD)hModule + imports->OriginalFirstThunk);
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD)hModule + imports->FirstThunk);

            for (; origThunk->u1.AddressOfData; origThunk++, thunk++) {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((DWORD)hModule + origThunk->u1.AddressOfData);
                if (strcmp((const char*)import->Name, funcName) == 0) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
                    *oldFunc = thunk->u1.Function;
                    thunk->u1.Function = newFunc;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD), oldProtect, &oldProtect);
                    return true;
                }
            }
        }
        return false;
    }

} // namespace Hooks
