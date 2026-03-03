#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <mutex>
#include <functional>
#include <cstdio>
#include "../Common/KOStructs.h"

// ============================================================
// Hooks v6 - Progressive Diagnostic Build
//
// v5 showed: hot-patch install is 100% correct, but runtime crash
// persists (even SEH didn't catch it). This suggests the crash
// is either in the calling mechanism itself, or a stack overflow.
//
// v6 Strategy: THREE HOOK MODES tested progressively
//   Mode 0: NAKED passthrough (just JMP to trampoline, zero code)
//   Mode 1: Minimal __stdcall passthrough (one CALL, no extras)
//   Mode 2: Full implementation (logging + packet capture + SEH)
//
// Start in Mode 0. If game survives, upgrade to Mode 1, then 2.
// This binary search finds exactly what causes the crash.
// ============================================================

namespace Hooks {

    typedef int (WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WINAPI* tRecv)(SOCKET s, char* buf, int len, int flags);

    // Hook mode: 0=naked, 1=passthrough, 2=full
    inline volatile LONG hookMode = 0;

    // Trampoline pointers - used by naked asm hooks
    // These MUST be simple globals (not volatile) for __asm access
    inline tSend g_origSend = nullptr;
    inline tRecv g_origRecv = nullptr;

    // Also keep volatile versions for C++ code paths
    inline volatile tSend oSend = nullptr;
    inline volatile tRecv oRecv = nullptr;

    inline volatile SOCKET gameSocket = INVALID_SOCKET;

    // Hooked function addresses
    inline DWORD sendFuncAddr = 0;
    inline DWORD recvFuncAddr = 0;

    // Original bytes for unhooking
    inline uint8_t sendOrigPad[5] = {};
    inline uint8_t sendOrigHead[2] = {};
    inline uint8_t recvOrigPad[5] = {};
    inline uint8_t recvOrigHead[2] = {};

    // Trampolines
    inline uint8_t* sendTrampoline = nullptr;
    inline uint8_t* recvTrampoline = nullptr;

    // Hook call counters
    inline volatile LONG sendHookCount = 0;
    inline volatile LONG recvHookCount = 0;
    inline volatile LONG sendCrashCount = 0;
    inline volatile LONG recvCrashCount = 0;

    // ==== Win32-only crash-safe logging (no CRT) ====
    inline HANDLE hHookLog = INVALID_HANDLE_VALUE;

    inline void RawLog(const char* msg) {
        if (hHookLog == INVALID_HANDLE_VALUE) {
            hHookLog = CreateFileA("BlessedBot_hook.log",
                GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        }
        if (hHookLog != INVALID_HANDLE_VALUE) {
            DWORD written;
            DWORD len = 0;
            const char* p = msg;
            while (*p++) len++;
            WriteFile(hHookLog, msg, len, &written, nullptr);
            FlushFileBuffers(hHookLog);
        }
    }

    inline void RawLogHex(const char* prefix, DWORD value) {
        char buf[80];
        const char* hex = "0123456789ABCDEF";
        int pos = 0;
        const char* p = prefix;
        while (*p && pos < 60) buf[pos++] = *p++;
        buf[pos++] = '0'; buf[pos++] = 'x';
        for (int i = 7; i >= 0; i--)
            buf[pos++] = hex[(value >> (i * 4)) & 0xF];
        buf[pos++] = '\n';
        buf[pos] = 0;
        RawLog(buf);
    }

    // ==== Install-time debug logging ====
    inline FILE* logFile = nullptr;
    inline char debugInfo[4096] = {};
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

    // Packet log (used in Mode 2 only)
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
        tSend fn = g_origSend;
        volatile SOCKET sock = gameSocket;
        if (fn && sock != INVALID_SOCKET)
            return fn(sock, (const char*)data, len, 0);
        return -1;
    }

    // ================================================================
    // MODE 0: NAKED PASSTHROUGH (absolute minimum - just JMP forward)
    // No prologue, no epilogue, no stack manipulation at all.
    // If this crashes, the trampoline itself is broken.
    // ================================================================
#pragma warning(push)
#pragma warning(disable: 4740) // inline asm suppresses global optimization
    __declspec(naked) static void hkSendNaked() {
        __asm {
            jmp dword ptr [g_origSend]
        }
    }

    __declspec(naked) static void hkRecvNaked() {
        __asm {
            jmp dword ptr [g_origRecv]
        }
    }
#pragma warning(pop)

    // ================================================================
    // MODE 1: MINIMAL PASSTHROUGH (proper __stdcall, one CALL only)
    // Tests that the calling convention is correct.
    // If Mode 0 works but this crashes, it's a calling convention issue.
    // ================================================================
    __declspec(noinline) static int __stdcall hkSendMinimal(SOCKET s, const char* buf, int len, int flags) {
        InterlockedIncrement(&sendHookCount);
        return g_origSend(s, buf, len, flags);
    }

    __declspec(noinline) static int __stdcall hkRecvMinimal(SOCKET s, char* buf, int len, int flags) {
        InterlockedIncrement(&recvHookCount);
        return g_origRecv(s, buf, len, flags);
    }

    // ================================================================
    // MODE 2: FULL IMPLEMENTATION (logging + packet capture + SEH)
    // ================================================================
    __declspec(noinline) static int __stdcall hkSendInner(SOCKET s, const char* buf, int len, int flags) {
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

        return g_origSend(s, buf, len, flags);
    }

    __declspec(noinline) static int __stdcall hkRecvInner(SOCKET s, char* buf, int len, int flags) {
        int result = g_origRecv(s, buf, len, flags);

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

    __declspec(noinline) static int __stdcall hkSendFull(SOCKET s, const char* buf, int len, int flags) {
        InterlockedIncrement(&sendHookCount);
        __try {
            return hkSendInner(s, buf, len, flags);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedIncrement(&sendCrashCount);
            return g_origSend(s, buf, len, flags);
        }
    }

    __declspec(noinline) static int __stdcall hkRecvFull(SOCKET s, char* buf, int len, int flags) {
        InterlockedIncrement(&recvHookCount);
        __try {
            return hkRecvInner(s, buf, len, flags);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedIncrement(&recvCrashCount);
            return g_origRecv(s, buf, len, flags);
        }
    }

    // ---- Hex dump helper ----
    inline void HexDump(DWORD addr, int count, char* out, int outSize) {
        int pos = 0;
        for (int i = 0; i < count && pos < outSize - 4; i++)
            pos += sprintf_s(out + pos, outSize - pos, "%02X ", *(uint8_t*)(addr + i));
    }

    // ---- Create hot-patch trampoline ----
    inline uint8_t* CreateHotPatchTrampoline(DWORD funcAddr) {
        uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, 16,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tramp) return nullptr;

        tramp[0] = 0x8B;
        tramp[1] = 0xFF;
        tramp[2] = 0xE9;
        DWORD jmpTarget = funcAddr + 2;
        *(int32_t*)(tramp + 3) = (int32_t)(jmpTarget - (DWORD)(tramp + 7));

        FlushInstructionCache(GetCurrentProcess(), tramp, 16);
        return tramp;
    }

    // ---- Apply hot-patch hook ----
    inline bool ApplyHotPatch(DWORD funcAddr, DWORD hookAddr,
        uint8_t* backupPad, uint8_t* backupHead, const char* name) {

        uint8_t* pFunc = (uint8_t*)funcAddr;

        if (pFunc[0] != 0x8B || pFunc[1] != 0xFF) {
            DbgLog("%s: NOT hot-patchable (bytes: %02X %02X, expected 8B FF)\n",
                name, pFunc[0], pFunc[1]);
            return false;
        }

        uint8_t* pPad = pFunc - 5;
        bool padOk = true;
        for (int i = 0; i < 5; i++) {
            if (pPad[i] != 0xCC && pPad[i] != 0x90 && pPad[i] != 0x00) {
                padOk = false;
                break;
            }
        }

        char hexBuf[64];
        HexDump((DWORD)pPad, 5, hexBuf, sizeof(hexBuf));
        DbgLog("%s: padding [-5]: %s (%s)\n", name, hexBuf, padOk ? "OK" : "NOT standard");

        memcpy(backupPad, pPad, 5);
        memcpy(backupHead, pFunc, 2);

        DWORD oldProt;
        if (!VirtualProtect(pPad, 7, PAGE_EXECUTE_READWRITE, &oldProt)) {
            DbgLog("%s: VirtualProtect failed: %d\n", name, GetLastError());
            return false;
        }

        pPad[0] = 0xE9;
        *(int32_t*)(pPad + 1) = (int32_t)(hookAddr - (DWORD)(pPad + 5));

        pFunc[0] = 0xEB;
        pFunc[1] = 0xF9;

        VirtualProtect(pPad, 7, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), pPad, 7);

        HexDump((DWORD)pPad, 7, hexBuf, sizeof(hexBuf));
        DbgLog("%s: patched [-5..+2]: %s\n", name, hexBuf);
        DbgLog("%s: hook -> 0x%08X, trampoline -> 0x%08X\n", name, hookAddr, funcAddr + 2);

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
        FlushInstructionCache(GetCurrentProcess(), pPad, 7);
        return true;
    }

    // ---- Install Hooks ----
    // mode: 0=naked, 1=minimal, 2=full
    inline bool InstallNetworkHooks(int mode = 0) {
        debugPos = 0;
        memset(debugInfo, 0, sizeof(debugInfo));
        hookMode = mode;

        const char* modeNames[] = { "NAKED passthrough", "MINIMAL passthrough", "FULL (logging+SEH)" };
        DbgLog("=== Hook Install v6 - Mode %d: %s ===\n", mode, modeNames[mode]);

        HMODULE hWsock = GetModuleHandleA("wsock32.dll");
        if (!hWsock) hWsock = LoadLibraryA("wsock32.dll");
        HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
        if (!hWs2) hWs2 = LoadLibraryA("ws2_32.dll");

        if (!hWsock) { DbgLog("FAIL: wsock32.dll not found\n"); return false; }

        DbgLog("wsock32.dll at: 0x%08X\n", (DWORD)hWsock);
        DbgLog("ws2_32.dll at: 0x%08X\n", (DWORD)hWs2);

        DWORD wsockSend = (DWORD)GetProcAddress(hWsock, "send");
        DWORD wsockRecv = (DWORD)GetProcAddress(hWsock, "recv");
        DWORD ws2Send = hWs2 ? (DWORD)GetProcAddress(hWs2, "send") : 0;

        char hexBuf[128];
        HexDump(wsockSend, 16, hexBuf, sizeof(hexBuf));
        DbgLog("wsock32.send (0x%08X): %s\n", wsockSend, hexBuf);
        HexDump(wsockRecv, 16, hexBuf, sizeof(hexBuf));
        DbgLog("wsock32.recv (0x%08X): %s\n", wsockRecv, hexBuf);

        DbgLog("wsock32.send == ws2_32.send? %s\n", wsockSend == ws2Send ? "YES (forwarded)" : "NO");

        sendFuncAddr = wsockSend;
        recvFuncAddr = wsockRecv;

        // Create trampolines
        sendTrampoline = CreateHotPatchTrampoline(sendFuncAddr);
        recvTrampoline = CreateHotPatchTrampoline(recvFuncAddr);

        if (!sendTrampoline || !recvTrampoline) {
            DbgLog("FAIL: Could not allocate trampolines\n");
            return false;
        }

        // Set BOTH volatile and non-volatile originals
        g_origSend = (tSend)sendTrampoline;
        g_origRecv = (tRecv)recvTrampoline;
        oSend = g_origSend;
        oRecv = g_origRecv;

        DbgLog("send trampoline: 0x%08X\n", (DWORD)sendTrampoline);
        DbgLog("recv trampoline: 0x%08X\n", (DWORD)recvTrampoline);
        DbgLog("g_origSend: 0x%08X\n", (DWORD)g_origSend);
        DbgLog("g_origRecv: 0x%08X\n", (DWORD)g_origRecv);

        HexDump((DWORD)sendTrampoline, 7, hexBuf, sizeof(hexBuf));
        DbgLog("send trampoline bytes: %s\n", hexBuf);
        HexDump((DWORD)recvTrampoline, 7, hexBuf, sizeof(hexBuf));
        DbgLog("recv trampoline bytes: %s\n", hexBuf);

        // Select hook functions based on mode
        DWORD hookSendAddr, hookRecvAddr;
        switch (mode) {
        case 0:
            hookSendAddr = (DWORD)&hkSendNaked;
            hookRecvAddr = (DWORD)&hkRecvNaked;
            DbgLog("Using NAKED hooks (zero overhead JMP)\n");
            break;
        case 1:
            hookSendAddr = (DWORD)&hkSendMinimal;
            hookRecvAddr = (DWORD)&hkRecvMinimal;
            DbgLog("Using MINIMAL hooks (stdcall passthrough)\n");
            break;
        default:
            hookSendAddr = (DWORD)&hkSendFull;
            hookRecvAddr = (DWORD)&hkRecvFull;
            DbgLog("Using FULL hooks (logging + SEH)\n");
            break;
        }

        DbgLog("hookSend at: 0x%08X\n", hookSendAddr);
        DbgLog("hookRecv at: 0x%08X\n", hookRecvAddr);

        // Dump first bytes of hook function to verify it's real code
        HexDump(hookSendAddr, 16, hexBuf, sizeof(hexBuf));
        DbgLog("hookSend bytes: %s\n", hexBuf);
        HexDump(hookRecvAddr, 16, hexBuf, sizeof(hexBuf));
        DbgLog("hookRecv bytes: %s\n", hexBuf);

        // Pre-hook log to file
        RawLog("=== v6 Hook Runtime Log ===\n");
        RawLogHex("Mode: ", (DWORD)mode);
        RawLogHex("g_origSend: ", (DWORD)g_origSend);
        RawLogHex("g_origRecv: ", (DWORD)g_origRecv);
        RawLog("Hooks about to be activated...\n");

        DbgLog("\nApplying hot-patches...\n");

        bool sendOk = ApplyHotPatch(sendFuncAddr, hookSendAddr, sendOrigPad, sendOrigHead, "send");
        bool recvOk = ApplyHotPatch(recvFuncAddr, hookRecvAddr, recvOrigPad, recvOrigHead, "recv");

        // Post-patch verification
        HexDump(sendFuncAddr, 8, hexBuf, sizeof(hexBuf));
        DbgLog("send now: %s\n", hexBuf);
        HexDump(recvFuncAddr, 8, hexBuf, sizeof(hexBuf));
        DbgLog("recv now: %s\n", hexBuf);

        DbgLog("\nResult: send=%s recv=%s\n", sendOk ? "OK" : "FAIL", recvOk ? "OK" : "FAIL");
        DbgLog("=== Hook Install Complete (Mode %d) ===\n", mode);

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
        g_origSend = nullptr;
        g_origRecv = nullptr;
        oSend = nullptr;
        oRecv = nullptr;
        if (logFile) { fclose(logFile); logFile = nullptr; }
        if (hHookLog != INVALID_HANDLE_VALUE) { CloseHandle(hHookLog); hHookLog = INVALID_HANDLE_VALUE; }
    }

    // ---- Get hook stats ----
    inline void GetHookStats(char* buf, int bufSize) {
        sprintf_s(buf, bufSize,
            "Mode %ld | Send: %ld (crash: %ld) | Recv: %ld (crash: %ld)",
            hookMode, sendHookCount, sendCrashCount, recvHookCount, recvCrashCount);
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
