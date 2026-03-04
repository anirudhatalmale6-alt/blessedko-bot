#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <functional>
#include "../Common/KOStructs.h"

// ============================================================
// Packet Parser - Extract KO packets from raw TCP stream
//
// KO wire format: AA 55 [size LE16] [opcode] [data...] 55 AA
//
// TCP can fragment or concatenate packets, so we buffer the
// stream and extract complete packets as they arrive.
// ============================================================

namespace PacketParser {

    constexpr uint8_t HDR_1 = 0xAA;
    constexpr uint8_t HDR_2 = 0x55;
    constexpr uint8_t FTR_1 = 0x55;
    constexpr uint8_t FTR_2 = 0xAA;

    // Parsed packet
    struct ParsedPacket {
        uint8_t  opcode;
        const uint8_t* payload;   // Points into buffer (after opcode)
        size_t   payloadLen;      // Length of data after opcode
        size_t   totalDataLen;    // Total data between header/footer (includes opcode)
        bool     isSend;
    };

    // Callback for each parsed packet
    using PacketHandler = std::function<void(const ParsedPacket& pkt)>;
    inline PacketHandler onPacket = nullptr;

    // Stream buffers
    inline std::vector<uint8_t> sendBuf;
    inline std::vector<uint8_t> recvBuf;

    // Stats
    inline volatile LONG parsedSendCount = 0;
    inline volatile LONG parsedRecvCount = 0;

    // Extract complete packets from buffer
    inline void Extract(std::vector<uint8_t>& buf, bool isSend) {
        while (buf.size() >= 8) { // Minimum: AA 55 [2] [1 opcode] 55 AA = 7, but we want at least 1 byte payload
            // Find AA 55 header
            size_t hdr = SIZE_MAX;
            for (size_t i = 0; i + 1 < buf.size(); i++) {
                if (buf[i] == HDR_1 && buf[i + 1] == HDR_2) {
                    hdr = i;
                    break;
                }
            }

            if (hdr == SIZE_MAX) {
                buf.clear();
                return;
            }

            // Discard junk before header
            if (hdr > 0)
                buf.erase(buf.begin(), buf.begin() + hdr);

            // Need header(2) + size(2) = 4 bytes minimum
            if (buf.size() < 4) return;

            uint16_t dataSize = buf[2] | (buf[3] << 8);

            // Sanity: data size should be 1..4096
            if (dataSize == 0 || dataSize > 4096) {
                buf.erase(buf.begin(), buf.begin() + 2); // Skip bad header
                continue;
            }

            // Total: header(2) + sizeField(2) + data(dataSize) + footer(2)
            size_t total = 4 + (size_t)dataSize + 2;

            if (buf.size() < total) return; // Incomplete, wait

            // Verify footer
            if (buf[4 + dataSize] != FTR_1 || buf[4 + dataSize + 1] != FTR_2) {
                buf.erase(buf.begin(), buf.begin() + 2); // Bad footer, skip header
                continue;
            }

            // Valid packet!
            ParsedPacket pkt;
            pkt.isSend = isSend;
            pkt.opcode = buf[4]; // First data byte = opcode
            pkt.totalDataLen = dataSize;
            pkt.payload = buf.data() + 5;       // After opcode
            pkt.payloadLen = dataSize > 1 ? dataSize - 1 : 0;

            if (isSend)
                InterlockedIncrement(&parsedSendCount);
            else
                InterlockedIncrement(&parsedRecvCount);

            if (onPacket)
                onPacket(pkt);

            // Remove processed packet
            buf.erase(buf.begin(), buf.begin() + total);
        }
    }

    // Feed raw TCP data from hooks
    inline void FeedSend(const uint8_t* data, int len) {
        if (len > 0) {
            sendBuf.insert(sendBuf.end(), data, data + len);
            Extract(sendBuf, true);
        }
    }

    inline void FeedRecv(const uint8_t* data, int len) {
        if (len > 0) {
            recvBuf.insert(recvBuf.end(), data, data + len);
            Extract(recvBuf, false);
        }
    }

    // Opcode name lookup
    inline const char* OpcodeName(uint8_t op) {
        switch (op) {
        case KO::Opcode::WIZ_MYINFO:          return "MYINFO";
        case KO::Opcode::WIZ_MOVE:            return "MOVE";
        case KO::Opcode::WIZ_ROTATE:          return "ROTATE";
        case KO::Opcode::WIZ_ATTACK:          return "ATTACK";
        case KO::Opcode::WIZ_HP_CHANGE:       return "HP_CHG";
        case KO::Opcode::WIZ_MSP_CHANGE:      return "MP_CHG";
        case KO::Opcode::WIZ_EXP_CHANGE:      return "EXP_CHG";
        case KO::Opcode::WIZ_TARGET_HP:       return "TGT_HP";
        case KO::Opcode::WIZ_ITEM_DROP:       return "ITEM_DROP";
        case KO::Opcode::WIZ_ITEM_PICKUP:     return "ITEM_PICK";
        case KO::Opcode::WIZ_ITEM_MOVE:       return "ITEM_MOVE";
        case KO::Opcode::WIZ_DEAD:            return "DEAD";
        case KO::Opcode::WIZ_NPC_EVENT:       return "NPC_EVENT";
        case KO::Opcode::WIZ_TRADE:           return "TRADE";
        case KO::Opcode::WIZ_ITEM_USE:        return "ITEM_USE";
        case KO::Opcode::WIZ_WARP:            return "WARP";
        case KO::Opcode::WIZ_ZONE_CHANGE:     return "ZONE_CHG";
        case KO::Opcode::WIZ_MAGIC_PROCESS:   return "SKILL";
        case KO::Opcode::WIZ_MAGIC_CANCEL:    return "SKILL_CXL";
        case KO::Opcode::WIZ_PARTY:           return "PARTY";
        case KO::Opcode::WIZ_BUFF:            return "BUFF";
        case KO::Opcode::WIZ_SELECT_TARGET:   return "SEL_TGT";
        case KO::Opcode::WIZ_RESURRECT:       return "RESURRECT";
        default: return nullptr;
        }
    }

    // Build opcode frequency table string
    inline void GetOpcodeStats(char* buf, int bufSize, volatile LONG counts[256]) {
        int pos = 0;
        for (int i = 0; i < 256 && pos < bufSize - 80; i++) {
            LONG c = counts[i];
            if (c == 0) continue;
            const char* name = OpcodeName((uint8_t)i);
            if (name)
                pos += sprintf_s(buf + pos, bufSize - pos, "  0x%02X %-12s: %ld\n", i, name, c);
            else
                pos += sprintf_s(buf + pos, bufSize - pos, "  0x%02X %-12s: %ld\n", i, "???", c);
        }
    }

} // namespace PacketParser
