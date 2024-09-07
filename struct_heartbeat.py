from pymavlink import mavutil
import time
import hashlib
import struct

# CRC calculation functions
def crc_accumulate(byte, crc):
    tmp = byte ^ (crc & 0xff)
    tmp ^= (tmp << 4) & 0xff
    return ((crc >> 8) & 0xff) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)

def crc_calculate(bytes, length):
    crc = 0xffff
    for i in range(length):
        crc = crc_accumulate(bytes[i], crc)
    return crc

# User input
seed = input("Enter seed: ")
secret_key = hashlib.sha256(seed.encode('utf-8')).hexdigest()
link_id = input("Enter link_id (in hex format): ")

# Heartbeat payload
TYPE = 6
AUTOPILOT = 8
BASE_MODE = 0
CUSTOM_MODE = 0
SYSTEM_STATUS = 0
MAVLink_version = 3

# Use struct to pack payload
payload = struct.pack('<BBBIBB', TYPE, AUTOPILOT, BASE_MODE, CUSTOM_MODE, SYSTEM_STATUS, MAVLink_version)

# Header fields
STX = 0XFD
LENGTH = len(payload)
INC = 1
CMP = 0
SEQ = 255
SYS_ID = 255
COMP_ID = 190
MSG_ID = [111, 111, 111]  # List of message ID bytes

# Use struct to pack header
header = struct.pack('<BBBBBB3B', STX, LENGTH, INC, CMP, SEQ, SYS_ID, COMP_ID, *MSG_ID)

# Remove STX and compute CRC on the rest of the header and payload
header_without_stx = header[1:]  # Exclude STX (first byte)
message_without_stx = header_without_stx + payload

# CRC_EXTRA value table (simplified for illustration)
crc_extra_list = [50, 124, 137, 0, 237, 217, 104, 119, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0, 0, 0, 214, 159, 220, 168, 24, 23, 170, 144,
67, 115, 39, 246, 185, 104, 237, 244, 222, 212, 9, 254, 230, 28, 28, 132, 221, 232, 11, 153, 41, 39, 214, 223,
141, 33, 15, 3, 100, 24, 239, 238, 30, 200, 183, 0, 130, 0, 148, 21, 0, 52, 124, 0, 0, 0, 20, 0, 152, 143, 0, 0]

message_id = 111  # Example message ID
crc = crc_calculate(message_without_stx, len(message_without_stx))
crc_extra = crc_extra_list[message_id]  # Retrieve corresponding CRC_EXTRA value

# Compute final CRC with CRC_EXTRA
crc = crc_accumulate(crc_extra, crc)

# Convert CRC to little-endian format
crc_hex = crc.to_bytes(2, 'little').hex()

# Timestamp (6 bytes from current time in microseconds)
current_time = int(time.time() * 1e6)
timestamp = current_time.to_bytes(8, 'little')[-6:]
timestamp_hex = timestamp.hex()

# Convert header, payload to hex
header_hex = header.hex()
payload_hex = payload.hex()

# Signature input: combine secret_key, header, payload, crc, link_id, and timestamp
signature_input_hex = secret_key + header_hex + payload_hex + crc_hex + link_id + timestamp_hex
signature_input_bytes = bytes.fromhex(signature_input_hex)

# Generate signature
hash_result = hashlib.sha256(signature_input_bytes).digest()
signature = hash_result[:6]  # Use first 6 bytes of hash result as signature

# Combine final message (header + payload + crc + link_id + timestamp + signature)
signed_msg = header + payload + bytes.fromhex(crc_hex) + bytes.fromhex(link_id) + timestamp + signature

# Send message
try:
    master = mavutil.mavlink_connection('udpout:10.0.2.5:14551')
    master.wait_heartbeat()
    master.write(signed_msg)
    print("Message sent")
except Exception as e:
    print("Error:", str(e))
