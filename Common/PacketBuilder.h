#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>

// ============================================================
// Packet Builder - Construct and parse KO game packets
// KO packet format: [size(2)] [encrypted(1)] [opcode(1)] [data...]
// ============================================================

namespace KO {

    class Packet {
    public:
        Packet() { m_data.reserve(256); }
        Packet(uint8_t opcode) {
            m_data.reserve(256);
            WriteByte(opcode);
        }

        // Write operations
        void WriteByte(uint8_t val) { m_data.push_back(val); }

        void WriteShort(uint16_t val) {
            m_data.push_back(val & 0xFF);
            m_data.push_back((val >> 8) & 0xFF);
        }

        void WriteInt(uint32_t val) {
            m_data.push_back(val & 0xFF);
            m_data.push_back((val >> 8) & 0xFF);
            m_data.push_back((val >> 16) & 0xFF);
            m_data.push_back((val >> 24) & 0xFF);
        }

        void WriteFloat(float val) {
            WriteInt(*reinterpret_cast<uint32_t*>(&val));
        }

        void WriteString(const char* str) {
            uint16_t len = (uint16_t)strlen(str);
            WriteShort(len);
            for (uint16_t i = 0; i < len; i++)
                m_data.push_back(str[i]);
        }

        void WriteBytes(const uint8_t* data, size_t len) {
            for (size_t i = 0; i < len; i++)
                m_data.push_back(data[i]);
        }

        // Read operations (for parsing received packets)
        void SetData(const uint8_t* data, size_t len) {
            m_data.assign(data, data + len);
            m_readPos = 0;
        }

        uint8_t ReadByte() {
            if (m_readPos >= m_data.size()) return 0;
            return m_data[m_readPos++];
        }

        uint16_t ReadShort() {
            uint16_t val = 0;
            if (m_readPos + 1 < m_data.size()) {
                val = m_data[m_readPos] | (m_data[m_readPos + 1] << 8);
                m_readPos += 2;
            }
            return val;
        }

        uint32_t ReadInt() {
            uint32_t val = 0;
            if (m_readPos + 3 < m_data.size()) {
                val = m_data[m_readPos] |
                    (m_data[m_readPos + 1] << 8) |
                    (m_data[m_readPos + 2] << 16) |
                    (m_data[m_readPos + 3] << 24);
                m_readPos += 4;
            }
            return val;
        }

        float ReadFloat() {
            uint32_t raw = ReadInt();
            return *reinterpret_cast<float*>(&raw);
        }

        std::string ReadString() {
            uint16_t len = ReadShort();
            std::string s;
            for (uint16_t i = 0; i < len && m_readPos < m_data.size(); i++)
                s += (char)m_data[m_readPos++];
            return s;
        }

        void ResetRead() { m_readPos = 0; }
        void SkipBytes(size_t n) { m_readPos += n; }

        // Access
        const uint8_t* Data() const { return m_data.data(); }
        size_t Size() const { return m_data.size(); }
        uint8_t GetOpcode() const { return m_data.empty() ? 0 : m_data[0]; }
        void Clear() { m_data.clear(); m_readPos = 0; }

        // Build full packet with header (for sending via hooked send)
        std::vector<uint8_t> BuildFull() const {
            std::vector<uint8_t> full;
            uint16_t totalLen = (uint16_t)(m_data.size() + 2); // +2 for size header
            full.push_back(totalLen & 0xFF);
            full.push_back((totalLen >> 8) & 0xFF);
            full.push_back(0); // encryption flag (0 = not encrypted for now)
            full.insert(full.end(), m_data.begin(), m_data.end());
            return full;
        }

    private:
        std::vector<uint8_t> m_data;
        size_t m_readPos = 0;
    };

    // ---- Common packet builders ----

    // Attack target
    inline Packet BuildAttackPacket(uint16_t targetId) {
        Packet p(Opcode::WIZ_ATTACK);
        p.WriteByte(0x01);          // Attack type: normal
        p.WriteByte(0x01);          // Result (success)
        p.WriteShort(targetId);     // Target ID
        return p;
    }

    // Cast skill
    inline Packet BuildSkillPacket(uint32_t skillId, uint16_t targetId,
        float srcX, float srcY, float srcZ,
        float dstX, float dstY, float dstZ) {
        Packet p(Opcode::WIZ_MAGIC_PROCESS);
        p.WriteByte(SkillSub::CASTING);
        p.WriteInt(skillId);
        p.WriteShort(targetId);
        // Source position
        p.WriteShort((uint16_t)(srcX * 10.0f));
        p.WriteShort((uint16_t)(srcY * 10.0f));
        p.WriteShort((uint16_t)(srcZ * 10.0f));
        // Target position
        p.WriteShort((uint16_t)(dstX * 10.0f));
        p.WriteShort((uint16_t)(dstY * 10.0f));
        p.WriteShort((uint16_t)(dstZ * 10.0f));
        return p;
    }

    // Pick up item
    inline Packet BuildLootPacket(uint32_t itemBundleId) {
        Packet p(Opcode::WIZ_ITEM_PICKUP);
        p.WriteInt(itemBundleId);
        return p;
    }

    // Use item (potion)
    inline Packet BuildUseItemPacket(uint32_t itemId, uint16_t slotPos) {
        Packet p(Opcode::WIZ_ITEM_USE);
        p.WriteInt(itemId);
        p.WriteShort(slotPos);
        return p;
    }

    // Select target
    inline Packet BuildSelectTarget(uint16_t targetId) {
        Packet p(Opcode::WIZ_SELECT_TARGET);
        p.WriteShort(targetId);
        return p;
    }

    // Warp/teleport
    inline Packet BuildWarpPacket(float x, float y, float z) {
        Packet p(Opcode::WIZ_WARP);
        p.WriteShort((uint16_t)(x * 10.0f));
        p.WriteShort((uint16_t)(y * 10.0f));
        p.WriteShort((uint16_t)(z * 10.0f));
        return p;
    }

} // namespace KO
