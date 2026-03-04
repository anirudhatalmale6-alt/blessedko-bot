#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstdio>

// ============================================================
// KODefender Bypass v2.1 - Minimal Stealth (No Monitored APIs)
//
// v1:   Modified KODefender IAT + code → detected by integrity scan
// v2:   Used VEH + hardware BPs → detected (SuspendThread,
//       SetThreadContext, CreateToolhelp32Snapshot are monitored)
// v2.1: ONLY uses direct memory writes. No suspicious API calls.
//
// Techniques (all are raw memory operations):
//   1. PEB Unlinking: remove DLL from loader lists (pointer writes)
//   2. PE Header Erasure: wipe MZ/PE signatures (memset)
//   3. PEB Anti-Debug: clear BeingDebugged/NtGlobalFlag (byte writes)
//
// Suspicious APIs used: NONE
// KODefender bytes modified: ZERO
// Game exe bytes modified: ZERO
// System DLL bytes modified: ZERO
// ============================================================

namespace Defender {

    inline FILE* logFile = nullptr;

    // ---- PEB structures for x86 ----
    typedef struct _UNICODE_STR {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STR;

    typedef struct _LDR_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID      DllBase;
        PVOID      EntryPoint;
        ULONG      SizeOfImage;
        UNICODE_STR FullDllName;
        UNICODE_STR BaseDllName;
    } LDR_ENTRY;

    inline void Log(const char* fmt, ...) {
        if (!logFile) fopen_s(&logFile, "BlessedBot_debug.log", "a");
        if (logFile) {
            va_list args;
            va_start(args, fmt);
            fprintf(logFile, "[DEF] ");
            vfprintf(logFile, fmt, args);
            va_end(args);
            fflush(logFile);
        }
    }

    // ================================================================
    // PEB Unlinking: Remove our DLL from all 3 loader lists
    //
    // Uses only: __readfsdword (inline), pointer dereferences, writes
    // No API calls. Safe to call from DllMain or any thread.
    // After unlinking, EnumProcessModules/GetModuleHandle can't find us.
    // ================================================================
    inline void UnlinkFromPEB(HMODULE hModule) {
        DWORD peb = __readfsdword(0x30);
        DWORD ldr = *(DWORD*)(peb + 0x0C); // PEB->Ldr

        // Walk InLoadOrderModuleList (at PEB_LDR_DATA+0x0C)
        PLIST_ENTRY head = (PLIST_ENTRY)(ldr + 0x0C);

        for (PLIST_ENTRY cur = head->Flink; cur != head; cur = cur->Flink) {
            LDR_ENTRY* entry = (LDR_ENTRY*)cur;

            if (entry->DllBase == (PVOID)hModule) {
                // Log name before unlinking
                if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
                    char nameBuf[64] = {};
                    WideCharToMultiByte(CP_ACP, 0, entry->BaseDllName.Buffer,
                        entry->BaseDllName.Length / 2, nameBuf, sizeof(nameBuf) - 1,
                        nullptr, nullptr);
                    Log("Unlinking: %s (base=0x%08X, size=0x%X)\n",
                        nameBuf, (DWORD)hModule, entry->SizeOfImage);
                }

                // Unlink from InLoadOrderModuleList
                entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
                entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;

                // Unlink from InMemoryOrderModuleList
                entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;
                entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;

                // Unlink from InInitializationOrderModuleList
                entry->InInitializationOrderLinks.Blink->Flink = entry->InInitializationOrderLinks.Flink;
                entry->InInitializationOrderLinks.Flink->Blink = entry->InInitializationOrderLinks.Blink;

                Log("Unlinked from all 3 PEB loader lists\n");
                return;
            }
        }
        Log("WARNING: Module 0x%08X not found in PEB\n", (DWORD)hModule);
    }

    // ================================================================
    // PE Header Erasure: Wipe our DLL's PE header from memory
    //
    // Uses only: VirtualProtect (on our OWN memory), memset
    // After erasure, memory scanners can't find MZ/PE signatures.
    // ================================================================
    inline void ErasePEHeader(HMODULE hModule) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
        DWORD imageSize = 0;

        // Read image size before erasing
        if (dos->e_magic == 0x5A4D) {
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hModule + dos->e_lfanew);
            if (nt->Signature == 0x00004550)
                imageSize = nt->OptionalHeader.SizeOfImage;
        }

        DWORD oldProt;
        if (VirtualProtect((void*)hModule, 0x1000, PAGE_READWRITE, &oldProt)) {
            SecureZeroMemory((void*)hModule, 0x1000);
            VirtualProtect((void*)hModule, 0x1000, oldProt, &oldProt);
            Log("PE header erased (image was 0x%X bytes)\n", imageSize);
        }
        else {
            Log("PE erase failed (error %d)\n", GetLastError());
        }
    }

    // ================================================================
    // Early Stealth: Called at the START of BotThread, before UI.
    //
    // Hides our DLL as fast as possible after injection to minimize
    // the window where KODefender's scan could spot us.
    // ================================================================
    inline void EarlyStealth(HMODULE hModule) {
        Log("\n=== Early Stealth (auto at load) ===\n");
        UnlinkFromPEB(hModule);
        ErasePEHeader(hModule);
        Log("DLL hidden from module lists + PE erased\n");
        Log("=== Early Stealth Complete ===\n\n");
    }

    // ================================================================
    // PEB Anti-Debug: Clear debug indicators
    //
    // Uses only: __readfsdword (inline), pointer writes
    // IsDebuggerPresent() literally returns PEB->BeingDebugged.
    // ================================================================
    inline void ClearPEBFlags() {
        DWORD peb = __readfsdword(0x30);

        // BeingDebugged (PEB+0x02) - stable across all Windows versions
        BYTE* pDebug = (BYTE*)(peb + 0x02);
        BYTE oldDebug = *pDebug;
        *pDebug = 0;
        Log("PEB->BeingDebugged: %d -> 0\n", oldDebug);

        // NtGlobalFlag (PEB+0x68) - stable across all Windows versions
        DWORD* pFlag = (DWORD*)(peb + 0x68);
        DWORD oldFlag = *pFlag;
        *pFlag = 0;
        Log("PEB->NtGlobalFlag: 0x%X -> 0\n", oldFlag);

        // NOTE: Heap flags NOT modified. Offsets vary by Windows version
        // (XP: +0x0C/+0x10, Win7+: different) and wrong offsets corrupt
        // the heap causing abort() cascades. Since BeingDebugged is already
        // 0 (we're injected, not debugged), heap flags are normal anyway.
    }

    // ================================================================
    // Install: Called when user clicks "Bypass Defender"
    //
    // By this point, EarlyStealth() has already hidden us.
    // This just clears anti-debug flags (simple memory writes).
    // ================================================================
    inline bool Install(HMODULE hOurModule) {
        Log("\n=== DefenderBypass v2.1 (Button Click) ===\n");

        HMODULE hDefender = GetModuleHandleA("KODefender.dll");
        Log("KODefender: %s (0x%08X)\n",
            hDefender ? "LOADED" : "not found", (DWORD)hDefender);

        // Clear anti-debug flags
        ClearPEBFlags();

        Log("\nSummary:\n");
        Log("  PEB unlinking: done (at load time)\n");
        Log("  PE header erasure: done (at load time)\n");
        Log("  Anti-debug flags: cleared\n");
        Log("  Suspicious API calls: NONE\n");
        Log("  KODefender bytes modified: ZERO\n");
        Log("=== DefenderBypass v2.1 Complete ===\n\n");

        return true;
    }

} // namespace Defender
