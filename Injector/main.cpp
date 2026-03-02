#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <filesystem>

// ============================================================
// BlessedKO Bot Injector
// Simple DLL injector using LoadLibrary method
// For Phase 1 testing - will upgrade to manual mapping later
// ============================================================

// Find process by name
DWORD FindProcess(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return 0;
}

// Standard LoadLibrary injection
bool InjectDLL(DWORD pid, const char* dllPath) {
    // Open target process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::cout << "[-] Failed to open process (Error: " << GetLastError() << ")\n";
        std::cout << "    Try running as Administrator!\n";
        return false;
    }

    // Get full path
    char fullPath[MAX_PATH];
    GetFullPathNameA(dllPath, MAX_PATH, fullPath, nullptr);

    // Check if DLL exists
    if (GetFileAttributesA(fullPath) == INVALID_FILE_ATTRIBUTES) {
        std::cout << "[-] DLL not found: " << fullPath << "\n";
        CloseHandle(hProc);
        return false;
    }

    std::cout << "[*] Injecting: " << fullPath << "\n";

    // Allocate memory in target process for the DLL path
    size_t pathLen = strlen(fullPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProc, nullptr, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cout << "[-] VirtualAllocEx failed (Error: " << GetLastError() << ")\n";
        CloseHandle(hProc);
        return false;
    }

    // Write DLL path to target process
    if (!WriteProcessMemory(hProc, remoteMem, fullPath, pathLen, nullptr)) {
        std::cout << "[-] WriteProcessMemory failed (Error: " << GetLastError() << ")\n";
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // Get LoadLibraryA address (same in all processes)
    FARPROC loadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLib) {
        std::cout << "[-] Cannot find LoadLibraryA\n";
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // Create remote thread to call LoadLibrary with our DLL path
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)loadLib, remoteMem, 0, nullptr);

    if (!hThread) {
        std::cout << "[-] CreateRemoteThread failed (Error: " << GetLastError() << ")\n";
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // Wait for injection to complete
    std::cout << "[*] Waiting for DLL to load...\n";
    WaitForSingleObject(hThread, 10000);

    // Check if DLL loaded
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode == 0) {
        std::cout << "[-] DLL failed to load in target process!\n";
        std::cout << "    KODefender may have blocked it.\n";
        std::cout << "    The Phase 2 manual mapper will solve this.\n";
    }
    else {
        std::cout << "[+] DLL loaded at: 0x" << std::hex << exitCode << "\n";
    }

    // Cleanup
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    return exitCode != 0;
}

int main() {
    std::cout << "=========================================\n";
    std::cout << "  BlessedKO Bot Injector v1.0\n";
    std::cout << "  Phase 1: Scanner & Hook Test\n";
    std::cout << "=========================================\n\n";

    // Find KnightOnLine.exe
    std::cout << "[*] Looking for KnightOnLine.exe...\n";
    DWORD pid = FindProcess("KnightOnLine.exe");

    if (!pid) {
        std::cout << "[-] KnightOnLine.exe not found!\n";
        std::cout << "[!] Start the game first, then run this injector.\n";
        std::cout << "\nPress any key to exit...";
        std::cin.get();
        return 1;
    }

    std::cout << "[+] Found KnightOnLine.exe (PID: " << std::dec << pid << ")\n";

    // Find our DLL (should be in same directory)
    std::string dllName = "BlessedBot.dll";

    // Check current directory
    if (GetFileAttributesA(dllName.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cout << "[-] " << dllName << " not found in current directory!\n";
        std::cout << "[!] Place BlessedBot.dll next to this injector.\n";
        std::cout << "\nPress any key to exit...";
        std::cin.get();
        return 1;
    }

    // Inject
    std::cout << "[*] Injecting " << dllName << " into KnightOnLine.exe...\n\n";

    if (InjectDLL(pid, dllName.c_str())) {
        std::cout << "\n[+] SUCCESS! Bot injected.\n";
        std::cout << "[+] The bot window should appear over the game.\n";
        std::cout << "[+] Follow the instructions in the bot window.\n";
    }
    else {
        std::cout << "\n[-] Injection failed.\n";
        std::cout << "[-] Tips:\n";
        std::cout << "    1. Run this injector as Administrator\n";
        std::cout << "    2. Make sure you're past the login screen\n";
        std::cout << "    3. Disable any antivirus temporarily\n";
    }

    std::cout << "\nPress any key to exit injector...";
    std::cin.get();
    return 0;
}
