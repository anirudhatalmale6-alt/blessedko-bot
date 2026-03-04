#pragma once
#include <Windows.h>
#include <cstdint>

// ============================================================
// BlessedKO Client v23xx - Memory Structures
// Based on USKO client reverse engineering
// These offsets need verification on the live client
// ============================================================

namespace KO {

    // Client base address
    constexpr DWORD CLIENT_BASE = 0x00400000;

    // ---- IAT Addresses (from PE analysis) ----
    namespace IAT {
        constexpr DWORD WS_SEND     = 0x00C53610;  // wsock32.send
        constexpr DWORD WS_RECV     = 0x00C53620;  // wsock32.recv
        constexpr DWORD WS_CONNECT  = 0x00C53608;  // wsock32.connect
    }

    // ---- Packet Opcodes (USKO standard) ----
    namespace Opcode {
        // Movement
        constexpr uint8_t WIZ_MOVE              = 0x06;
        constexpr uint8_t WIZ_ROTATE            = 0x07;

        // Combat
        constexpr uint8_t WIZ_ATTACK            = 0x08;
        constexpr uint8_t WIZ_MAGIC_PROCESS     = 0x2C;  // Skill cast
        constexpr uint8_t WIZ_MAGIC_CANCEL      = 0x2D;

        // Target
        constexpr uint8_t WIZ_TARGET_HP         = 0x17;

        // Item / Loot
        constexpr uint8_t WIZ_ITEM_DROP         = 0x1A;
        constexpr uint8_t WIZ_ITEM_PICKUP       = 0x1B;
        constexpr uint8_t WIZ_ITEM_MOVE         = 0x22;

        // Character info
        constexpr uint8_t WIZ_MYINFO            = 0x01;
        constexpr uint8_t WIZ_HP_CHANGE         = 0x13;
        constexpr uint8_t WIZ_MSP_CHANGE        = 0x14;
        constexpr uint8_t WIZ_EXP_CHANGE        = 0x15;

        // Party
        constexpr uint8_t WIZ_PARTY             = 0x2F;

        // Trade
        constexpr uint8_t WIZ_TRADE             = 0x20;

        // Warp/Zone
        constexpr uint8_t WIZ_WARP              = 0x25;
        constexpr uint8_t WIZ_ZONE_CHANGE       = 0x26;

        // NPC interaction
        constexpr uint8_t WIZ_NPC_EVENT         = 0x1E;

        // Buff
        constexpr uint8_t WIZ_BUFF              = 0x31;

        // Selection
        constexpr uint8_t WIZ_SELECT_TARGET     = 0x3A;

        // Death
        constexpr uint8_t WIZ_DEAD              = 0x12;
        constexpr uint8_t WIZ_RESURRECT         = 0x34;

        // Supply/Potion
        constexpr uint8_t WIZ_ITEM_USE          = 0x3C;

        // BlessedKO v23xx confirmed opcodes
        constexpr uint8_t WIZ_NPC_INOUT         = 0x0B;  // Entity spawn/despawn
        constexpr uint8_t WIZ_HEARTBEAT          = 0xE9;  // Custom keepalive
    }

    // ---- Skill cast sub-opcodes ----
    namespace SkillSub {
        constexpr uint8_t CASTING               = 0x01;
        constexpr uint8_t FLYING                = 0x02;
        constexpr uint8_t EFFECT_IN             = 0x03;
        constexpr uint8_t EFFECT_SELF           = 0x04;
        constexpr uint8_t CANCEL                = 0x05;
    }

    // ---- Player structure (CPlayerMySelf) ----
    // These are ESTIMATED offsets for v23xx - need verification
    // The scanner tool will help find exact offsets
    struct PlayerOffsets {
        static constexpr DWORD ID               = 0x0004;   // Player ID (short)
        static constexpr DWORD NAME             = 0x0008;   // Character name (char[20])
        static constexpr DWORD LEVEL            = 0x0060;   // Level (byte)
        static constexpr DWORD CLASS            = 0x005C;   // Class (short)
        static constexpr DWORD NATION           = 0x0058;   // Nation (byte) 1=Karus, 2=Elmorad
        static constexpr DWORD HP               = 0x0064;   // Current HP (int)
        static constexpr DWORD MAX_HP           = 0x0068;   // Max HP (int)
        static constexpr DWORD MP               = 0x006C;   // Current MP (int)
        static constexpr DWORD MAX_MP           = 0x0070;   // Max MP (int)

        // Position (float)
        static constexpr DWORD POS_X            = 0x0110;   // X coordinate
        static constexpr DWORD POS_Y            = 0x0114;   // Y (height)
        static constexpr DWORD POS_Z            = 0x0118;   // Z coordinate

        // Target
        static constexpr DWORD TARGET_ID        = 0x01A0;   // Current target ID
        static constexpr DWORD TARGET_HP_PCT    = 0x01A4;   // Target HP percentage

        // State
        static constexpr DWORD IS_DEAD          = 0x01B0;   // Dead flag
        static constexpr DWORD IS_MOVING        = 0x01B4;   // Moving flag
        static constexpr DWORD IS_ATTACKING     = 0x01B8;   // Attacking flag

        // Zone
        static constexpr DWORD ZONE_ID          = 0x0050;   // Current zone
    };

    // ---- Skill slot structure ----
    struct SkillSlot {
        uint32_t skillId;           // 0x00 - Skill table ID
        uint8_t  level;             // 0x04 - Skill level
        uint8_t  pad[3];
        float    cooldownRemaining; // 0x08 - Cooldown timer
        float    cooldownTotal;     // 0x0C - Total cooldown
        uint16_t mpCost;            // 0x10 - MP cost
        uint16_t range;             // 0x12 - Cast range
    };

    // ---- NPC/Mob structure ----
    struct NPCOffsets {
        static constexpr DWORD ID               = 0x0004;
        static constexpr DWORD NPC_ID           = 0x0008;   // NPC table ID
        static constexpr DWORD HP_PCT           = 0x0064;   // HP percentage
        static constexpr DWORD POS_X            = 0x0110;
        static constexpr DWORD POS_Y            = 0x0114;
        static constexpr DWORD POS_Z            = 0x0118;
        static constexpr DWORD IS_DEAD          = 0x01B0;
        static constexpr DWORD NATION           = 0x0058;
    };

    // ---- Pointer chain hints ----
    // CPlayerMySelf is typically a global singleton
    // Pattern: look for "CPlayerMySelf" RTTI, then find xrefs to the vtable
    // Or scan for known HP value pattern
    namespace Globals {
        // These will be found by the scanner
        static DWORD pPlayerMySelf      = 0;    // Pointer to CPlayerMySelf instance
        static DWORD pGameProcMain      = 0;    // Pointer to CGameProcMain
        static DWORD pUIManager         = 0;    // Pointer to CUIManager
        static DWORD pMagicSkillMng     = 0;    // Pointer to CMagicSkillMng
        static DWORD pPlayerOtherMgr    = 0;    // Pointer to CPlayerOtherMgr (other players/NPCs)
        static DWORD fnSendPacket       = 0;    // Address of packet send function
        static DWORD fnRecvPacket       = 0;    // Address of packet recv handler
    }

} // namespace KO
