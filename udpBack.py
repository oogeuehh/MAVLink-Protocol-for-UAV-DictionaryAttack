import socket
import struct
import time
import hashlib

# 用户输入部分
def user_input(prompt):
    return input(prompt).strip()

secret_key = user_input("Enter secret key: ").encode('utf-8')
link_id = bytes.fromhex(user_input("Enter link id: "))
header = bytes.fromhex(user_input("Enter header: "))

# MAVLink CRC 算法实现
def mavlink_crc(message):
    crc = 0xFFFF
    for byte in message:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x1021
            else:
                crc >>= 1
    return crc

# 建立UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 无人机的IP和端口
target_ip = "10.0.2.5"
target_port = 55419

# MAVLink command parameters (example for RETURN_TO_LAUNCH)
target_system = 1
target_component = 1
command_id = 20  # MAV_CMD_NAV_RETURN_TO_LAUNCH 的命令ID

# 构建payload
param1 = 0
param2 = 0
param3 = 0
param4 = 0
param5 = 0
param6 = 0
param7 = 0

# 根据 MAVLink 协议格式化消息 (Little-endian '<' for MAVLink 2.0)
payload = struct.pack('<I', command_id) + struct.pack('<7f', param1, param2, param3, param4, param5, param6, param7)

# 生成完整消息
message = header + payload

# 计算 CRC
crc = mavlink_crc(message)
crc_bytes = struct.pack('<H', crc)

# 添加时间戳
timestamp = int(time.time()).to_bytes(4, 'little')

# 生成签名
signature_input = secret_key + header + payload + crc_bytes + link_id + timestamp
hash_result = hashlib.sha256(signature_input).digest()
signature = hash_result[:6]

# 最终的消息包括: header + payload + crc + link_id + timestamp + signature
signed_msg = message + crc_bytes + link_id + timestamp + signature

# 发送消息
try:
    sock.sendto(signed_msg, (target_ip, target_port))
    print("Message sent successfully")
except Exception as e:
    print(f"Failed to send message: {e}")
finally:
    sock.close()
