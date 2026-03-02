#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <mutex>
#include <functional>
#include "../Common/KOStructs.h"

// ============================================================
// Hooks - IAT hooking for send/recv + KODefender bypass
// Uses IAT patching (simple, reliable for KO)
// ============================================================

namespace Hooks {

    // Original function pointers
    typedef int (WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WINAPI* tRecv)(SOCKET s, char* buf, int len, int flags);

    inline tSend oSend = nullptr;
    inline tRecv oRecv = nullptr;
    inline SOCKET gameSocket = INVALID_SOCKET;

    // Packet log entry
    struct PacketLog {
        bool     isSend;        // true = outgoing, false = incoming
        DWORD    timestamp;
        std::vector<uint8_t> data;
    };

    // Packet log buffer (circular, last 1000 packets)
    inline std::vector<PacketLog> packetLog;
    inline std::mutex logMutex;
    constexpr size_t MAX_LOG_SIZE = 1000;

    // Callback for packet interception
    using PacketCallback = std::function<bool(bool isSend, const uint8_t* data, int len)>;
    inline PacketCallback onPacket = nullptr;

    // Send packet through the game's socket
    inline int SendGamePacket(const uint8_t* data, int len) {
        if (oSend && gameSocket != INVALID_SOCKET) {
            return oSend(gameSocket, (const char*)data, len, 0);
        }
        return -1;
    }

    // Hooked send function
    inline int WINAPI hkSend(SOCKET s, const char* buf, int len, int flags) {
        // Capture the game socket
        if (gameSocket == INVALID_SOCKET)
            gameSocket = s;

        // Log the packet
        {
            std::lock_guard<std::mutex> lock(logMutex);
            PacketLog entry;
            entry.isSend = true;
            entry.timestamp = GetTickCount();
            entry.data.assign((uint8_t*)buf, (uint8_t*)buf + len);
            packetLog.push_back(entry);
            if (packetLog.size() > MAX_LOG_SIZE)
                packetLog.erase(packetLog.begin());
        }

        // Call callback if set (can modify/block packets)
        if (onPacket) {
            bool allow = onPacket(true, (const uint8_t*)buf, len);
            if (!allow) return len; // pretend we sent it
        }

        return oSend(s, buf, len, flags);
    }

    // Hooked recv function
    inline int WINAPI hkRecv(SOCKET s, char* buf, int len, int flags) {
        int result = oRecv(s, buf, len, flags);

        if (result > 0) {
            // Log the packet
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

            // Call callback
            if (onPacket) {
                onPacket(false, (const uint8_t*)buf, result);
            }
        }

        return result;
    }

    // ---- IAT Hook Helper ----
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

    // Direct IAT address patching (when we know the exact IAT address)
    inline bool PatchIATDirect(DWORD iatAddr, DWORD newFunc, DWORD* oldFunc) {
        DWORD oldProtect;
        if (VirtualProtect((void*)iatAddr, sizeof(DWORD), PAGE_READWRITE, &oldProtect)) {
            *oldFunc = *(DWORD*)iatAddr;
            *(DWORD*)iatAddr = newFunc;
            VirtualProtect((void*)iatAddr, sizeof(DWORD), oldProtect, &oldProtect);
            return true;
        }
        return false;
    }

    // ---- Install Hooks ----
    inline bool InstallNetworkHooks() {
        HMODULE hGame = GetModuleHandleA(nullptr); // KnightOnLine.exe

        bool sendOk = PatchIAT(hGame, "wsock32.dll", "send", (DWORD)hkSend, (DWORD*)&oSend);
        bool recvOk = PatchIAT(hGame, "wsock32.dll", "recv", (DWORD)hkRecv, (DWORD*)&oRecv);

        return sendOk && recvOk;
    }

    // ---- Remove Hooks ----
    inline void RemoveNetworkHooks() {
        if (oSend) {
            HMODULE hGame = GetModuleHandleA(nullptr);
            DWORD dummy;
            PatchIAT(hGame, "wsock32.dll", "send", (DWORD)oSend, &dummy);
            oSend = nullptr;
        }
        if (oRecv) {
            HMODULE hGame = GetModuleHandleA(nullptr);
            DWORD dummy;
            PatchIAT(hGame, "wsock32.dll", "recv", (DWORD)oRecv, &dummy);
            oRecv = nullptr;
        }
    }

} // namespace Hooks
