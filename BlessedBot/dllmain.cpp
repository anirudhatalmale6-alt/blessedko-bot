#include <Windows.h>
#include <cstdio>
#include <thread>
#include <chrono>

#include "DefenderBypass.h"
#include "Hooks.h"
#include "MemoryScanner.h"
#include "BotUI.h"
#include "../Common/KOStructs.h"
#include "../Common/PacketBuilder.h"
#include "../Common/PatternScanner.h"

// ============================================================
// BlessedKO Bot - DLL Entry Point
// v8: Indirect call-site hooking (MOV reg,[IAT] patching)
// ============================================================

static HMODULE g_hModule = nullptr;
static bool g_running = false;
static bool g_hooksInstalled = false;
static bool g_defenderBypassed = false;

// ---- Helper: show debug info in UI ----
static void ShowDebugInfo(const char* prefix) {
    char* line = Hooks::debugInfo;
    while (*line) {
        char* nl = strchr(line, '\n');
        if (nl) {
            *nl = 0;
            char logLine[512];
            sprintf_s(logLine, "%s %s", prefix, line);
            BotUI::Log(logLine);
            *nl = '\n';
            line = nl + 1;
        }
        else {
            char logLine[512];
            sprintf_s(logLine, "%s %s", prefix, line);
            BotUI::Log(logLine);
            break;
        }
    }
}

// ---- Button callbacks ----

void OnScanClick() {
    BotUI::Log("[*] Starting memory scan...");
    BotUI::SetStatus("Status: Scanning...");

    auto result = MemScanner::ScanAll();
    BotUI::Log(result.log);

    if (result.success) {
        BotUI::SetStatus("Status: Scan complete");
    }
    else {
        BotUI::SetStatus("Status: Scan failed");
    }
}

void OnHookClick() {
    if (g_hooksInstalled) {
        BotUI::Log("[!] Hooks already installed");
        return;
    }

    BotUI::Log("[*] Installing hooks v8 (indirect call-site)...");
    BotUI::Log("[*] Strategy: Patch MOV reg,[IAT] in game code");
    BotUI::Log("[*] System DLL bytes: UNTOUCHED");
    BotUI::Log("[*] IAT entries: UNTOUCHED");
    BotUI::Log("");

    if (Hooks::InstallNetworkHooks()) {
        g_hooksInstalled = true;
        ShowDebugInfo("[*]");

        // Count send vs recv patches
        size_t sendPatches = 0, recvPatches = 0;
        for (auto& site : Hooks::patchedSites) {
            if (site.isSend) sendPatches++;
            else recvPatches++;
        }

        char msg[256];
        sprintf_s(msg, "[+] Hooks active! %zu send + %zu recv MOV sites patched",
            sendPatches, recvPatches);
        BotUI::Log(msg);
        BotUI::Log("[+] wsock32/ws2_32 bytes: UNMODIFIED (KODefender safe!)");
        BotUI::Log("[+] IAT entries: UNMODIFIED");
        BotUI::Log("[+] Packet capture is LIVE");
        BotUI::SetStatus("Status: Hooks active (v8 indirect)");
    }
    else {
        BotUI::Log("[-] No indirect call sites found!");
        ShowDebugInfo("[-]");
        BotUI::Log("");
        BotUI::Log("[!] Check BlessedBot_debug.log for scan details");
        BotUI::SetStatus("Status: Hook failed - check logs");
    }
}

void OnBypassClick() {
    if (g_defenderBypassed) {
        BotUI::Log("[!] Defender already bypassed");
        return;
    }

    BotUI::Log("[*] Bypassing KODefender (v2.2)...");
    BotUI::Log("[*] Strategy: PEB flags only (no heap, no VEH)");
    BotUI::Log("[*] DLL already hidden at load time");

    HMODULE hDefender = GetModuleHandleA("KODefender.dll");
    if (!hDefender) {
        BotUI::Log("[!] KODefender.dll not loaded - nothing to bypass");
        g_defenderBypassed = true;
        BotUI::SetStatus("Status: No defender (safe)");
        return;
    }

    BotUI::Log("[*] KODefender found, clearing debug flags...");

    if (Defender::Install(g_hModule)) {
        g_defenderBypassed = true;
        BotUI::Log("[+] Anti-debug flags cleared");
        BotUI::Log("[+] DLL hidden (PEB unlink) + PE erased (at load)");
        BotUI::SetStatus("Status: Stealth active");
    }
    else {
        BotUI::Log("[-] Bypass failed!");
    }
}

void OnDumpClick() {
    if (!g_hooksInstalled) {
        BotUI::Log("[!] Install hooks first!");
        return;
    }

    char statsBuf[256];
    Hooks::GetHookStats(statsBuf, sizeof(statsBuf));
    char statsLine[300];
    sprintf_s(statsLine, "[*] Hook stats: %s", statsBuf);
    BotUI::Log(statsLine);

    std::lock_guard<std::mutex> lock(Hooks::logMutex);

    char buf[256];
    sprintf_s(buf, "[*] Packet log: %zu packets captured", Hooks::packetLog.size());
    BotUI::Log(buf);

    size_t start = Hooks::packetLog.size() > 20 ? Hooks::packetLog.size() - 20 : 0;
    for (size_t i = start; i < Hooks::packetLog.size(); i++) {
        auto& pkt = Hooks::packetLog[i];
        std::string hex;
        char hexBuf[4];

        size_t showLen = pkt.data.size() > 32 ? 32 : pkt.data.size();
        for (size_t j = 0; j < showLen; j++) {
            sprintf_s(hexBuf, "%02X ", pkt.data[j]);
            hex += hexBuf;
        }
        if (pkt.data.size() > 32) hex += "...";

        sprintf_s(buf, "  %s [%3zu bytes] %s",
            pkt.isSend ? "SEND" : "RECV",
            pkt.data.size(),
            hex.c_str());
        BotUI::Log(buf);

        if (pkt.data.size() >= 3) {
            uint8_t opcode = pkt.data[2];
            const char* opName = "UNKNOWN";
            switch (opcode) {
            case KO::Opcode::WIZ_MOVE:          opName = "WIZ_MOVE"; break;
            case KO::Opcode::WIZ_ATTACK:         opName = "WIZ_ATTACK"; break;
            case KO::Opcode::WIZ_MAGIC_PROCESS:  opName = "WIZ_MAGIC_PROCESS"; break;
            case KO::Opcode::WIZ_HP_CHANGE:      opName = "WIZ_HP_CHANGE"; break;
            case KO::Opcode::WIZ_MSP_CHANGE:     opName = "WIZ_MSP_CHANGE"; break;
            case KO::Opcode::WIZ_EXP_CHANGE:     opName = "WIZ_EXP_CHANGE"; break;
            case KO::Opcode::WIZ_ITEM_PICKUP:    opName = "WIZ_ITEM_PICKUP"; break;
            case KO::Opcode::WIZ_DEAD:           opName = "WIZ_DEAD"; break;
            case KO::Opcode::WIZ_BUFF:           opName = "WIZ_BUFF"; break;
            case KO::Opcode::WIZ_SELECT_TARGET:  opName = "WIZ_SELECT_TARGET"; break;
            case KO::Opcode::WIZ_TARGET_HP:      opName = "WIZ_TARGET_HP"; break;
            }
            if (strcmp(opName, "UNKNOWN") != 0) {
                sprintf_s(buf, "         -> Opcode 0x%02X = %s", opcode, opName);
                BotUI::Log(buf);
            }
        }
    }
}

void OnTestReadClick() {
    BotUI::Log("[*] Testing memory read at known game addresses...");

    HMODULE hGame = GetModuleHandleA(nullptr);
    if (!hGame) {
        BotUI::Log("[-] Cannot get game module!");
        return;
    }

    char buf[512];

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hGame;
    sprintf_s(buf, "[+] DOS magic: 0x%04X (should be 0x5A4D)", dos->e_magic);
    BotUI::Log(buf);

    // Check IAT entries
    DWORD sendPtr = *(DWORD*)KO::IAT::WS_SEND;
    DWORD recvPtr = *(DWORD*)KO::IAT::WS_RECV;
    sprintf_s(buf, "[+] IAT send -> 0x%08X", sendPtr);
    BotUI::Log(buf);
    sprintf_s(buf, "[+] IAT recv -> 0x%08X", recvPtr);
    BotUI::Log(buf);

    // Verify send/recv function bytes are UNMODIFIED
    uint8_t* sendBytes = (uint8_t*)sendPtr;
    uint8_t* recvBytes = (uint8_t*)recvPtr;
    sprintf_s(buf, "[+] send bytes: %02X %02X %02X (should be 8B FF 55)",
        sendBytes[0], sendBytes[1], sendBytes[2]);
    BotUI::Log(buf);
    sprintf_s(buf, "[+] recv bytes: %02X %02X %02X (should be 8B FF 55)",
        recvBytes[0], recvBytes[1], recvBytes[2]);
    BotUI::Log(buf);

    BotUI::Log("[+] Memory read test complete");
}

// ---- Main bot thread ----
void BotThread() {
    // FIRST: Hide our DLL immediately (before anything else!)
    // This minimizes the window where KODefender can spot us
    Defender::EarlyStealth(g_hModule);

    Sleep(1000); // Reduced from 2s - we're already hidden

    BotUI::Create((HINSTANCE)g_hModule);

    BotUI::onScanClick = OnScanClick;
    BotUI::onHookClick = OnHookClick;
    BotUI::onBypassClick = OnBypassClick;
    BotUI::onDumpClick = OnDumpClick;
    BotUI::onTestReadClick = OnTestReadClick;

    BotUI::Log("=== BlessedKO Bot v8.3 ===");
    BotUI::Log("Network: MOV reg,[IAT] indirect patching");
    BotUI::Log("Stealth: PEB unlink + PE erase (auto at load)");
    BotUI::Log("==========================================");
    BotUI::Log("");
    BotUI::Log("[+] DLL auto-hidden from module lists at load!");
    BotUI::Log("[+] PE header erased - no MZ/PE signatures");
    BotUI::Log("");
    BotUI::Log("Instructions:");
    BotUI::Log("1. Click 'Bypass Defender' (clears debug flags)");
    BotUI::Log("2. Click 'Hook Net' to capture packets");
    BotUI::Log("3. Play normally, then 'Dump Packets'");
    BotUI::Log("");

    char buf[128];
    sprintf_s(buf, "[+] DLL base: 0x%08X", (DWORD)g_hModule);
    BotUI::Log(buf);

    BotUI::SetStatus("Status: Stealth active - bypass defender next");

    BotUI::MessageLoop();
}

// ---- DLL Entry Point ----
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);

        g_running = true;
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            BotThread();
            return 0;
        }, nullptr, 0, nullptr);
        break;

    case DLL_PROCESS_DETACH:
        g_running = false;
        if (g_hooksInstalled) {
            Hooks::RemoveNetworkHooks();
        }
        if (BotUI::hMainWnd) {
            DestroyWindow(BotUI::hMainWnd);
        }
        break;
    }
    return TRUE;
}
