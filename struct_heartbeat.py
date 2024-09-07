import time
import hashlib
import struct
import socket

def crc_accumulate(byte, crc):
    tmp = byte ^ (crc & 0xff)
    tmp ^= (tmp << 4) & 0xff
    return ((crc >> 8) & 0xff) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)

def crc_calculate(bytes, length):
    crc = 0xffff
    for i in range(length):
        crc = crc_accumulate(bytes[i], crc)
    return crc

# 用户输入
seed = input("Enter seed: ")
secreteKey = hashlib.sha256(seed.encode('utf-8')).hexdigest()
linkid = input("Enter linkid (in hex format): ")


# Heartbeat payload
TYPE = 0x06
AUTOPILOT = 0x08
BASE_MODE = 0x00
CUSTOM_MODE = struct.pack('4B', 0x00, 0x00, 0x00, 0x00)
SYSTEM_STATUS = 0x00
MAVLink_version = 0x03

# Use struct to pack payload
payload = struct.pack('<BBB4sBB', TYPE, AUTOPILOT, BASE_MODE, CUSTOM_MODE, SYSTEM_STATUS, MAVLink_version)

# Header fields
STX = 0XFD
LENGTH = len(payload)
INC = 1
CMP = 0
SEQ = 255
SYS_ID = 255
COMP_ID = 190
MSG_ID = struct.pack('3B', 0x00, 0x00, 0x00)

# Use struct to pack header
header = struct.pack('<BBBBBBB3s', STX, LENGTH, INC, CMP, SEQ, SYS_ID, COMP_ID, MSG_ID)

# Remove STX and compute CRC on the rest of the header and payload
header_without_stx = header[1:]  # Exclude STX (first byte)
message_without_stx = header_without_stx + payload


# SIGNATURE
# CRC_EXTRA value table
crc_extra_list = [50, 124, 137, 0, 237, 217, 104, 119, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0, 0, 0, 214, 159, 220, 168, 24, 23, 170, 144,
67, 115, 39, 246, 185, 104, 237, 244, 222, 212, 9, 254, 230, 28, 28, 132, 221, 232, 11, 153, 41, 39, 214, 223,
141, 33, 15, 3, 100, 24, 239, 238, 30, 200, 183, 0, 130, 0, 148, 21, 0, 52, 124, 0, 0, 0, 20, 0, 152, 143, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 231, 183, 63, 54, 0, 0, 0, 0, 0, 0, 0, 175, 102, 158, 208, 56, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 204, 49, 170, 44, 83, 46, 0]

message_id = 0
crc = crc_calculate(message_without_stx, len(message_without_stx))
crc_extra = crc_extra_list[message_id]

# CRC_EXTRA --> final CRC
crc = crc_accumulate(crc_extra, crc)

crc_hex = crc.to_bytes(2, 'little').hex()

currentTime = int(time.time() * 1e6)
timestamp = currentTime.to_bytes(8, 'little')[-6:]  # 截取低 6 字节
timestamp_hex = timestamp.hex()

header_hex = header.hex()
payload_hex = payload.hex()


signature_input_hex = secreteKey + header_hex + payload_hex + crc_hex + linkid + timestamp_hex

signature_input_bytes = bytes.fromhex(signature_input_hex)

# 生成签名
hash_result = hashlib.sha256(signature_input_bytes).digest()
signature = hash_result[:6]

# 组合最终的消息
signed_msg = header + payload + bytes.fromhex(crc_hex) + bytes.fromhex(linkid) + timestamp + signature


uavip = "10.0.2.5"
port = 14551

# send message
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(signed_msg, (uavip, port))
    print("message sent")
except Exception as e:
    print("error:", str(e))
finally:
    sock.close()
