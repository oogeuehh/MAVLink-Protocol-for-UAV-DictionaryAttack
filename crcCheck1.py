import struct


def crc_accumulate(byte, crc):
    tmp = byte ^ (crc & 0xff)
    tmp ^= (tmp << 4) & 0xff
    return ((crc >> 8) & 0xff) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)


def crc_calculate(bytes, length):
    crc = 0xffff
    for i in range(length):
        crc = crc_accumulate(bytes[i], crc)
    return crc


# 这是一个列表，里面存放了mavlink协议中的所有消息的CRC_EXTRA值
# 例如心跳包的MSG_ID为0,对应的就是列表中的第一个CRC_EXTRA值，为50
# 参考 https://github.com/mavlink/mavlink/issues/30
lst = [50, 124, 137, 0, 237, 217, 104, 119, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0, 0, 0, 214, 159, 220, 168, 24, 23, 170, 144,
       67, 115, 39, 246, 185, 104, 237, 244, 222, 212, 9, 254, 230, 28, 28, 132, 221, 232, 11, 153, 41, 39, 214, 223,
       141, 33, 15, 3, 100, 24, 239, 238, 30, 200, 183, 0, 130, 0, 148, 21, 0, 52, 124, 0, 0, 0, 20, 0, 152, 143, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 231, 183, 63, 54, 0, 0, 0, 0, 0, 0, 0, 175, 102, 158, 208, 56, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 204, 49, 170, 44, 83, 46, 0]


# 定义各个字段的值
STX = 0xFD  # mavlink2.0的起始字节
LEN = 0x9  # payload的长度（单位为byte）
INC = 0
CMP = 0
SEQ = 1
SYSID = 1
COMPID = 1
MSGID = [0, 0, 0]  # 3 bytes
PAYLOAD = [0, 0, 0, 0, 2, 3, 0x51, 1, 3]
checksum_a = 0x4a  # 期望的结果, 从wireshark中得到的
checksum_b = 0xa9  # 期望的结果, 从wireshark中得到的
SIGNATURE = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # 13 bytes 但是这里不使用签名

# Calculate checksum over the full header and all payload bytes
header = struct.pack('<BBBBBB3s', LEN, INC, CMP, SEQ, SYSID, COMPID, bytes(MSGID))
payload = bytes(PAYLOAD)
# 先把MSG_ID转变为int
msgid = int.from_bytes(bytes(MSGID), byteorder='little')
print("msgid: ", msgid)
CRC_EXTRA = lst[msgid]
checksum = crc_calculate(header + payload, len(header) + len(payload))

# Add CRC_EXTRA to the checksum
checksum = crc_accumulate(CRC_EXTRA, checksum)

# Extract checksum_a and checksum_b
checksum_a = checksum & 0xFF
checksum_b = (checksum >> 8) & 0xFF

# 打印checksum_a和checksum_b,以十六进制的形式
print(hex(checksum_a), hex(checksum_b))
