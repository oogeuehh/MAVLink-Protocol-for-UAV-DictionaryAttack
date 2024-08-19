import socket
import struct
import time
import hashlib

# 用户输入部分
def user_input(prompt):
    return input(prompt).strip()

secret_key = user_input("Enter secret key: ").encode('utf-8')
link_id = bytes.fromhex(user_input("Enter link id: "))

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

# 获取当前时间戳
def get_timestamp():
    return int(time.time()).to_bytes(4, 'little')

# 获取消息 ID
def get_message_id():
    return 20  # MAV_CMD_NAV_RETURN_TO_LAUNCH 的命令ID

# MAVLink 2 构建函数
def build_mavlink_message(secret_key, target_ip, target_port, target_system, target_component):
    # MAVLink command parameters (example for RETURN_TO_LAUNCH)
    command_id = get_message_id()  # 20 为 MAV_CMD_NAV_RETURN_TO_LAUNCH 的命令ID

    # 构建payload
    payload = struct.pack('<B', target_system) + struct.pack('<B', target_component) + struct.pack('<H', command_id) + struct.pack('<7f', 0, 0, 0, 0, 0, 0, 0)

    # Header 构建
    sequence = 0  # 序列号 (可以设为任意值，但每条消息应递增)
    system_id = 1  # 发送系统的 ID
    component_id = 1  # 发送组件的 ID
    message_id = get_message_id()

    # 计算长度（不包括头部和 CRC）
    payload_length = len(payload)
    header_length = 6  # STX, Length, Sequence, System ID, Component ID, Message ID
    message_length = header_length + payload_length + 2  # 头部 + payload + CRC

    # 生成 Header
    header = struct.pack('<B', 0xFE)  # STX
    header += struct.pack('<B', payload_length + 6)  # Length (包括 header 和 CRC)
    header += struct.pack('<B', sequence)  # Sequence
    header += struct.pack('<B', system_id)  # System ID
    header += struct.pack('<B', component_id)  # Component ID
    header += struct.pack('<B', message_id)  # Message ID

    # 生成完整消息
    message = header + payload

    # 计算 CRC
    crc = mavlink_crc(message)
    crc_bytes = struct.pack('<H', crc)

    # 添加时间戳
    timestamp = get_timestamp()

    # 生成签名
    signature_input = secret_key + header + payload + crc_bytes + link_id + timestamp
    hash_result = hashlib.sha256(signature_input).digest()
    signature = hash_result[:6]  # SHA256_48, 取前 6 个字节

    # 最终的消息包括: header + payload + crc + link_id + timestamp + signature
    signed_msg = message + crc_bytes + link_id + timestamp + signature

    return signed_msg

# 发送消息
def send_message(signed_msg, target_ip, target_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(signed_msg, (target_ip, target_port))
        print("Message sent successfully")
    except Exception as e:
        print(f"Failed to send message: {e}")
    finally:
        sock.close()

# 配置
target_ip = "10.0.2.5"
target_port = 55419
target_system = 1
target_component = 1

# 构造并发送消息
signed_msg = build_mavlink_message(secret_key, target_ip, target_port, target_system, target_component)
send_message(signed_msg, target_ip, target_port)
