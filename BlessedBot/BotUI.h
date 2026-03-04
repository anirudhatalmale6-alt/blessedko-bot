#pragma once
#include <Windows.h>
#include <CommCtrl.h>
#include <string>
#include <functional>

#pragma comment(lib, "comctl32.lib")

// ============================================================
// Bot UI - External window for controlling the bot
// Simple Win32 window with status display and controls
// ============================================================

namespace BotUI {

    // Control IDs
    enum {
        ID_STATUS_TEXT = 1001,
        ID_LOG_TEXT,
        ID_BTN_SCAN,
        ID_BTN_HOOK,
        ID_BTN_BYPASS,
        ID_BTN_DUMP_PACKETS,
        ID_BTN_CLEAR_LOG,
        ID_BTN_TEST_READ,
        ID_BTN_START_BOT,
        ID_BTN_STOP_BOT,
        ID_BTN_AUTO_ATK,
        ID_BTN_AUTO_LOOT,
        ID_BTN_SHOW_STATE,
        ID_BTN_SHOW_OPCODES,
        ID_LABEL_HP,
        ID_LABEL_MP,
        ID_LABEL_POS,
        ID_LABEL_TARGET,
        ID_LABEL_ZONE,
        ID_LABEL_NAME,
        ID_BTN_RESET_STATS,
    };

    // Window handles
    inline HWND hMainWnd = nullptr;
    inline HWND hLogEdit = nullptr;
    inline HWND hStatusLabel = nullptr;
    inline HWND hHPLabel = nullptr;
    inline HWND hMPLabel = nullptr;
    inline HWND hPosLabel = nullptr;
    inline HWND hTargetLabel = nullptr;
    inline HWND hZoneLabel = nullptr;
    inline HWND hNameLabel = nullptr;

    // Callbacks
    inline std::function<void()> onScanClick;
    inline std::function<void()> onHookClick;
    inline std::function<void()> onBypassClick;
    inline std::function<void()> onDumpClick;
    inline std::function<void()> onTestReadClick;
    inline std::function<void()> onStartBotClick;
    inline std::function<void()> onStopBotClick;
    inline std::function<void()> onAutoAtkClick;
    inline std::function<void()> onAutoLootClick;
    inline std::function<void()> onShowStateClick;
    inline std::function<void()> onShowOpcodesClick;
    inline std::function<void()> onResetClick;

    // Append text to log
    inline void Log(const char* text) {
        if (!hLogEdit) return;

        int len = GetWindowTextLengthA(hLogEdit);
        SendMessageA(hLogEdit, EM_SETSEL, len, len);
        SendMessageA(hLogEdit, EM_REPLACESEL, FALSE, (LPARAM)text);
        SendMessageA(hLogEdit, EM_REPLACESEL, FALSE, (LPARAM)"\r\n");
        SendMessageA(hLogEdit, EM_SCROLLCARET, 0, 0);
    }

    inline void Log(const std::string& text) {
        Log(text.c_str());
    }

    // Update status labels
    inline void SetStatus(const char* text) {
        if (hStatusLabel) SetWindowTextA(hStatusLabel, text);
    }

    inline void SetHP(const char* text) { if (hHPLabel) SetWindowTextA(hHPLabel, text); }
    inline void SetMP(const char* text) { if (hMPLabel) SetWindowTextA(hMPLabel, text); }
    inline void SetPos(const char* text) { if (hPosLabel) SetWindowTextA(hPosLabel, text); }
    inline void SetTarget(const char* text) { if (hTargetLabel) SetWindowTextA(hTargetLabel, text); }
    inline void SetZone(const char* text) { if (hZoneLabel) SetWindowTextA(hZoneLabel, text); }
    inline void SetName(const char* text) { if (hNameLabel) SetWindowTextA(hNameLabel, text); }

    // Window procedure
    inline LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
            case ID_BTN_SCAN:
                if (onScanClick) onScanClick();
                break;
            case ID_BTN_HOOK:
                if (onHookClick) onHookClick();
                break;
            case ID_BTN_BYPASS:
                if (onBypassClick) onBypassClick();
                break;
            case ID_BTN_DUMP_PACKETS:
                if (onDumpClick) onDumpClick();
                break;
            case ID_BTN_CLEAR_LOG:
                if (hLogEdit) SetWindowTextA(hLogEdit, "");
                break;
            case ID_BTN_TEST_READ:
                if (onTestReadClick) onTestReadClick();
                break;
            case ID_BTN_START_BOT:
                if (onStartBotClick) onStartBotClick();
                break;
            case ID_BTN_STOP_BOT:
                if (onStopBotClick) onStopBotClick();
                break;
            case ID_BTN_AUTO_ATK:
                if (onAutoAtkClick) onAutoAtkClick();
                break;
            case ID_BTN_AUTO_LOOT:
                if (onAutoLootClick) onAutoLootClick();
                break;
            case ID_BTN_SHOW_STATE:
                if (onShowStateClick) onShowStateClick();
                break;
            case ID_BTN_SHOW_OPCODES:
                if (onShowOpcodesClick) onShowOpcodesClick();
                break;
            case ID_BTN_RESET_STATS:
                if (onResetClick) onResetClick();
                break;
            }
            break;

        case WM_CLOSE:
            ShowWindow(hWnd, SW_HIDE);
            return 0; // Don't destroy, just hide

        case WM_DESTROY:
            hMainWnd = nullptr;
            break;
        }
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }

    // Helper to create a label
    inline HWND CreateLabel(HWND parent, int x, int y, int w, int h, const char* text, int id = 0) {
        return CreateWindowExA(0, "STATIC", text,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            x, y, w, h, parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
    }

    // Helper to create a button
    inline HWND CreateBtn(HWND parent, int x, int y, int w, int h, const char* text, int id) {
        return CreateWindowExA(0, "BUTTON", text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, y, w, h, parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
    }

    // Create the main bot window
    inline bool Create(HINSTANCE hInst) {
        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = WndProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = "BlessedBotWnd";
        RegisterClassExA(&wc);

        hMainWnd = CreateWindowExA(
            WS_EX_TOPMOST,
            "BlessedBotWnd",
            "BlessedKO Bot v2.1 - Isolation Ready",
            WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
            100, 100, 620, 640,
            nullptr, nullptr, hInst, nullptr
        );

        if (!hMainWnd) return false;

        // ---- Status Section ----
        CreateLabel(hMainWnd, 10, 10, 580, 15, "=== BlessedKO Bot - Phase 1: Scanner & Hook Test ===");

        hStatusLabel = CreateLabel(hMainWnd, 10, 30, 400, 15, "Status: Not initialized");
        hStatusLabel = CreateWindowExA(0, "STATIC", "Status: Not initialized",
            WS_CHILD | WS_VISIBLE, 10, 30, 400, 15, hMainWnd, (HMENU)ID_STATUS_TEXT, nullptr, nullptr);

        // Player info labels
        CreateLabel(hMainWnd, 10, 55, 50, 15, "Name:");
        hNameLabel = CreateLabel(hMainWnd, 60, 55, 200, 15, "N/A", ID_LABEL_NAME);

        CreateLabel(hMainWnd, 10, 75, 30, 15, "HP:");
        hHPLabel = CreateLabel(hMainWnd, 40, 75, 150, 15, "N/A", ID_LABEL_HP);

        CreateLabel(hMainWnd, 200, 75, 30, 15, "MP:");
        hMPLabel = CreateLabel(hMainWnd, 230, 75, 150, 15, "N/A", ID_LABEL_MP);

        CreateLabel(hMainWnd, 10, 95, 30, 15, "Pos:");
        hPosLabel = CreateLabel(hMainWnd, 40, 95, 300, 15, "N/A", ID_LABEL_POS);

        CreateLabel(hMainWnd, 10, 115, 50, 15, "Target:");
        hTargetLabel = CreateLabel(hMainWnd, 60, 115, 200, 15, "None", ID_LABEL_TARGET);

        CreateLabel(hMainWnd, 300, 115, 40, 15, "Zone:");
        hZoneLabel = CreateLabel(hMainWnd, 340, 115, 100, 15, "N/A", ID_LABEL_ZONE);

        // ---- Row 1: Phase 1 buttons ----
        int btnY = 145;
        CreateBtn(hMainWnd, 10, btnY, 120, 28, "Scan Memory", ID_BTN_SCAN);
        CreateBtn(hMainWnd, 140, btnY, 120, 28, "Hook Net", ID_BTN_HOOK);
        CreateBtn(hMainWnd, 270, btnY, 120, 28, "Bypass Defender", ID_BTN_BYPASS);

        // ---- Row 2: Phase 1 tools ----
        CreateBtn(hMainWnd, 10, btnY + 32, 120, 28, "Dump Packets", ID_BTN_DUMP_PACKETS);
        CreateBtn(hMainWnd, 140, btnY + 32, 120, 28, "Test Read", ID_BTN_TEST_READ);
        CreateBtn(hMainWnd, 270, btnY + 32, 120, 28, "Clear Log", ID_BTN_CLEAR_LOG);

        // ---- Row 3: Phase 2 bot controls ----
        CreateLabel(hMainWnd, 10, btnY + 68, 580, 1, ""); // separator
        CreateBtn(hMainWnd, 10, btnY + 72, 90, 28, "Start Bot", ID_BTN_START_BOT);
        CreateBtn(hMainWnd, 105, btnY + 72, 90, 28, "Stop Bot", ID_BTN_STOP_BOT);
        CreateBtn(hMainWnd, 200, btnY + 72, 90, 28, "Auto Atk", ID_BTN_AUTO_ATK);
        CreateBtn(hMainWnd, 295, btnY + 72, 90, 28, "Auto Loot", ID_BTN_AUTO_LOOT);

        // ---- Row 4: Phase 2 info ----
        CreateBtn(hMainWnd, 10, btnY + 104, 90, 28, "Game State", ID_BTN_SHOW_STATE);
        CreateBtn(hMainWnd, 105, btnY + 104, 90, 28, "Opcodes", ID_BTN_SHOW_OPCODES);
        CreateBtn(hMainWnd, 200, btnY + 104, 90, 28, "Reset", ID_BTN_RESET_STATS);

        // ---- Log area ----
        hLogEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            10, btnY + 140, 580, 250,
            hMainWnd, (HMENU)ID_LOG_TEXT, nullptr, nullptr);

        // Set monospace font for log
        HFONT hFont = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
        SendMessageA(hLogEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

        ShowWindow(hMainWnd, SW_SHOW);
        UpdateWindow(hMainWnd);

        return true;
    }

    // Message pump (run in separate thread)
    inline void MessageLoop() {
        MSG msg;
        while (GetMessageA(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }

    // Toggle visibility
    inline void Toggle() {
        if (hMainWnd) {
            if (IsWindowVisible(hMainWnd))
                ShowWindow(hMainWnd, SW_HIDE);
            else
                ShowWindow(hMainWnd, SW_SHOW);
        }
    }

} // namespace BotUI
