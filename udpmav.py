import socket
import struct
import time
import hashlib

def user_input(prompt):
    return input(prompt).strip()
    
secreteKey = user_input("Enter secrete key: ").encode('utf-8')
linkid = bytes.fromhex(user_input("Enter linkid: "))

# crc calculation
def mavlink_crc(message):
    crc = 0xFFFF
    for byte in message:
        crc ^= (byte<<8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1)^0x1021
            else:
                crc <<=1
    return crc
    
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

target_ip = "10.0.2.5"
target_port = 48307
target_system = 1
target_component = 1
message_id = 76
    
param1 = 1.0
param2 = 3.0
param3 = 0.0
param4 = 0.0
param5 = 0.0
param6 = 0,0
param7 = 0,0
command = 176
target_sys = target_system
target_comp = target_component
comfirmation = 0

payload = struct.pack('<7fHBBB', param1, param2, param3, param4, param5, param6, param7, command, target_sys, target_comp, comfirmation)

stx = 0xFD
payload_length = len(payload)
inc = 1
cmp = 0
sequence = 0
system_id = 255
component_id = 190
message_id = 76
messgae_id_bytes = struct.pack('<I', message_id)[:3]

header = struct.pack('<BBBBBBB3B', stx, payload_length, inc, cmp, sequence, system_id, component_id, *messgae_id_bytes)
    
message = header + payload

currentTime = int(time.time() * 1e6)
timestamp = struct.pack('<Q', currentTime)[:6]

crc = mavlink_crc(message)
crc_bytes = struct.pack('<H', crc)

signature_input = secreteKey + header + payload + crc_bytes + linkid + timestamp
hash_result = hashlib.sha256(signature_input).digest()
signature = hash_result[:6]
signed_msg = message + crc_bytes + linkid + timestamp + signature

try:
    sock.sendto(signed_msg, (target_ip, target_port))
    print("message sended")
except Exception as e:
    print(f"error: {e}")
finally:
    sock.close()


