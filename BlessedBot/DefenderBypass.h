#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include "../Common/PatternScanner.h"
#include "Hooks.h"

// ============================================================
// KODefender Bypass
// Neutralizes the client-side anti-cheat (KODefender.dll)
//
// Detected protections:
// - Process scanning (Cheat Engine, OllyDbg, IDA, Process Hacker, etc.)
// - Memory integrity checks (CRC/"memory editing" detection)
// - Debugger detection (IsDebuggerPresent, GetThreadContext)
// - Speed hack detection
// - Wallhack detection
// - Module enumeration
//
// Strategy: Hook the key Windows APIs that KODefender uses for scanning,
// and patch its scanning threads to skip detection.
// ============================================================

namespace Defender {

    // ---- API hooks to neutralize scanning ----

    // Hook IsDebuggerPresent to always return FALSE
    typedef BOOL(WINAPI* tIsDebuggerPresent)();
    inline tIsDebuggerPresent oIsDebuggerPresent = nullptr;
    inline BOOL WINAPI hkIsDebuggerPresent() {
        return FALSE;
    }

    // Hook K32EnumProcesses to filter out our injector
    typedef BOOL(WINAPI* tEnumProcesses)(DWORD*, DWORD, LPDWORD);
    inline tEnumProcesses oEnumProcesses = nullptr;
    inline BOOL WINAPI hkEnumProcesses(DWORD* lpidProcess, DWORD cb, LPDWORD lpcbNeeded) {
        return oEnumProcesses(lpidProcess, cb, lpcbNeeded);
        // Note: We could filter PIDs here, but since our injector closes after injection,
        // there's nothing to filter. This hook is a safety net.
    }

    // Hook K32GetModuleBaseNameA to hide any suspicious module names
    typedef DWORD(WINAPI* tGetModuleBaseNameA)(HANDLE, HMODULE, LPSTR, DWORD);
    inline tGetModuleBaseNameA oGetModuleBaseNameA = nullptr;
    inline DWORD WINAPI hkGetModuleBaseNameA(HANDLE hProcess, HMODULE hModule, LPSTR lpBaseName, DWORD nSize) {
        DWORD result = oGetModuleBaseNameA(hProcess, hModule, lpBaseName, nSize);
        if (result > 0) {
            // List of process names KODefender scans for
            const char* blocked[] = {
                "cheatengine", "ollydbg", "x64dbg", "x32dbg", "ida",
                "processhacker", "processexplorer", "wireshark",
                "fiddler", "rpe", "mypackettool", "trainer"
            };

            std::string name(lpBaseName);
            // Convert to lowercase for comparison
            for (auto& c : name) c = (char)tolower(c);

            for (const char* b : blocked) {
                if (name.find(b) != std::string::npos) {
                    // Replace with a harmless name
                    strcpy_s(lpBaseName, nSize, "svchost.exe");
                    return (DWORD)strlen("svchost.exe");
                }
            }
        }
        return result;
    }

    // Hook ReadProcessMemory to prevent KODefender from scanning our DLL
    typedef BOOL(WINAPI* tReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    inline tReadProcessMemory oReadProcessMemory = nullptr;
    inline DWORD ourDllBase = 0;
    inline DWORD ourDllSize = 0;

    inline BOOL WINAPI hkReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
        // If KODefender tries to read our DLL's memory, return zeros
        DWORD addr = (DWORD)lpBaseAddress;
        if (ourDllBase && addr >= ourDllBase && addr < ourDllBase + ourDllSize) {
            if (lpBuffer) memset(lpBuffer, 0, nSize);
            if (lpNumberOfBytesRead) *lpNumberOfBytesRead = nSize;
            return TRUE;
        }
        return oReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }

    // ---- Patch KODefender's scanning functions directly ----

    // NOP out the scanning threads in KODefender.dll
    inline bool PatchDefenderScans(HMODULE hDefender) {
        if (!hDefender) return false;

        // Find the "An 3rd party tools has been detected" string
        DWORD strAddr = Scanner::FindString(hDefender, "An 3rd party tools has been detected");
        if (strAddr) {
            // Find xrefs to this string - these are the detection functions
            auto xrefs = Scanner::FindXRefs(hDefender, strAddr);
            for (DWORD xref : xrefs) {
                // Walk backwards to find the function start, then NOP the call
                // or patch the conditional jump to always skip detection
                // For safety, we patch the comparison that triggers detection
                // Look for JZ/JNZ near the xref and flip it
                for (int i = -32; i < 0; i++) {
                    uint8_t* ptr = (uint8_t*)(xref + i);
                    // JZ (0x74) or JNZ (0x75) - flip the condition
                    if (*ptr == 0x74 || *ptr == 0x75) {
                        DWORD oldProt;
                        VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &oldProt);
                        *ptr = (*ptr == 0x74) ? 0x75 : 0x74; // flip JZ <-> JNZ
                        VirtualProtect(ptr, 1, oldProt, &oldProt);
                        break;
                    }
                }
            }
        }

        // Find and patch "Game closed due to memory editing"
        DWORD memEditStr = Scanner::FindString(hDefender, "Game closed due to memory editing");
        if (memEditStr) {
            auto xrefs = Scanner::FindXRefs(hDefender, memEditStr);
            for (DWORD xref : xrefs) {
                for (int i = -32; i < 0; i++) {
                    uint8_t* ptr = (uint8_t*)(xref + i);
                    if (*ptr == 0x74 || *ptr == 0x75) {
                        DWORD oldProt;
                        VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &oldProt);
                        *ptr = (*ptr == 0x74) ? 0x75 : 0x74;
                        VirtualProtect(ptr, 1, oldProt, &oldProt);
                        break;
                    }
                }
            }
        }

        // Find and patch "Cheat Detected"
        DWORD cheatStr = Scanner::FindString(hDefender, "Cheat Detected");
        if (cheatStr) {
            auto xrefs = Scanner::FindXRefs(hDefender, cheatStr);
            for (DWORD xref : xrefs) {
                for (int i = -32; i < 0; i++) {
                    uint8_t* ptr = (uint8_t*)(xref + i);
                    if (*ptr == 0x74 || *ptr == 0x75) {
                        DWORD oldProt;
                        VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &oldProt);
                        *ptr = (*ptr == 0x74) ? 0x75 : 0x74;
                        VirtualProtect(ptr, 1, oldProt, &oldProt);
                        break;
                    }
                }
            }
        }

        // Find "speedhack" detection and patch
        DWORD speedStr = Scanner::FindString(hDefender, "speedhack");
        if (speedStr) {
            auto xrefs = Scanner::FindXRefs(hDefender, speedStr);
            for (DWORD xref : xrefs) {
                for (int i = -32; i < 0; i++) {
                    uint8_t* ptr = (uint8_t*)(xref + i);
                    if (*ptr == 0x74 || *ptr == 0x75) {
                        DWORD oldProt;
                        VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &oldProt);
                        *ptr = (*ptr == 0x74) ? 0x75 : 0x74;
                        VirtualProtect(ptr, 1, oldProt, &oldProt);
                        break;
                    }
                }
            }
        }

        return true;
    }

    // ---- Install all bypasses ----
    inline bool Install(HMODULE ourModule) {
        // Store our DLL info for ReadProcessMemory hook
        if (ourModule) {
            ourDllBase = (DWORD)ourModule;
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ourModule;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(ourDllBase + dos->e_lfanew);
            ourDllSize = nt->OptionalHeader.SizeOfImage;
        }

        HMODULE hDefender = GetModuleHandleA("KODefender.dll");

        // 1. Hook APIs in KODefender's IAT
        if (hDefender) {
            // IsDebuggerPresent
            Hooks::PatchIAT(hDefender, "KERNEL32.dll", "IsDebuggerPresent",
                (DWORD)hkIsDebuggerPresent, (DWORD*)&oIsDebuggerPresent);

            // K32EnumProcesses
            Hooks::PatchIAT(hDefender, "KERNEL32.dll", "K32EnumProcesses",
                (DWORD)hkEnumProcesses, (DWORD*)&oEnumProcesses);

            // K32GetModuleBaseNameA
            Hooks::PatchIAT(hDefender, "KERNEL32.dll", "K32GetModuleBaseNameA",
                (DWORD)hkGetModuleBaseNameA, (DWORD*)&oGetModuleBaseNameA);

            // ReadProcessMemory
            Hooks::PatchIAT(hDefender, "KERNEL32.dll", "ReadProcessMemory",
                (DWORD)hkReadProcessMemory, (DWORD*)&oReadProcessMemory);

            // 2. Patch detection strings/branches in KODefender
            PatchDefenderScans(hDefender);
        }

        // 3. Also hook in the main exe (it also calls IsDebuggerPresent)
        HMODULE hGame = GetModuleHandleA(nullptr);
        if (hGame && !oIsDebuggerPresent) {
            Hooks::PatchIAT(hGame, "kernel32.dll", "IsDebuggerPresent",
                (DWORD)hkIsDebuggerPresent, (DWORD*)&oIsDebuggerPresent);
        }

        return true;
    }

} // namespace Defender
