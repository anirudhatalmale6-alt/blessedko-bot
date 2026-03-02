# BlessedKO Bot v1.0 - Phase 1

Scanner & Hook Validation Tool for BlessedKO private server.

## Build Instructions

### Requirements
- **Visual Studio 2022** (Community edition is free)
- **Windows SDK 10.0** (installed with VS)

### Steps
1. Open `BlessedKOXP.sln` in Visual Studio 2022
2. Set configuration to **Release | x86** (top toolbar)
3. Build → Build Solution (Ctrl+Shift+B)
4. Output files will be in `Build/Release/`:
   - `BlessedBot.dll` - The bot DLL
   - `BlessedBotInjector.exe` - The injector

## Usage

1. Start BlessedKO and log in to your character
2. Make sure you're in-game (not on character select)
3. **Run `BlessedBotInjector.exe` as Administrator**
4. The bot window will appear over the game
5. Follow the on-screen instructions:
   - Click **Bypass Defender** first
   - Click **Hook Net** to intercept packets
   - Click **Scan Memory** to find game structures
   - Click **Test Read** to verify memory access
   - Play normally, then click **Dump Packets** to see captured data

## Phase 1 Features
- [x] DLL injection into KnightOnLine.exe
- [x] KODefender.dll bypass (anti-cheat neutralization)
- [x] Network hook (send/recv packet interception)
- [x] Memory scanner (RTTI + pattern based)
- [x] Packet logger with opcode identification
- [x] External control window

## Project Structure
```
BlessedKOXP/
├── BlessedKOXP.sln          # Visual Studio solution
├── Common/                   # Shared headers
│   ├── KOStructs.h          # Game memory structures & offsets
│   ├── PacketBuilder.h      # Packet construction/parsing
│   └── PatternScanner.h     # Memory pattern scanner
├── BlessedBot/              # Bot DLL project
│   ├── dllmain.cpp          # Entry point
│   ├── BotUI.h              # Win32 UI window
│   ├── DefenderBypass.h     # KODefender neutralization
│   ├── Hooks.h              # IAT hooking for send/recv
│   └── MemoryScanner.h      # Game structure finder
└── Injector/                # Injector EXE project
    └── main.cpp             # Process injection
```

## Important Notes
- Always run the injector **as Administrator**
- The bot window stays on top of the game
- Close button hides the window (doesn't unload)
- To unload: close the game
- This is Phase 1 - bot automation comes in Phase 2
