from pymavlink import mavutil
import time
import hashlib
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

# 用户输入
seed = input("Enter seed: ")
secreteKey = hashlib.sha256(seed.encode('utf-8')).hexdigest()
linkid = input("Enter linkid (in hex format): ")

def build_message():
    target_system = 1
    target_component = 1
    # 创建 MAVLink 消息
    command = mavutil.mavlink.MAVLink_command_long_message(
        target_system=target_system,
        target_component=target_component,
        command=mavutil.mavlink.MAV_CMD_NAV_RETURN_TO_LAUNCH,
        confirmation=0,
        param1=1.0, param2=3.0, param3=0, 
        param4=0, param5=0, param6=0, param7=0
    )
    return command

# 构建消息
command_message = build_message()

# 打包消息，获取完整的消息（包含头部和 payload）
packed_message = command_message.pack(mavutil.mavlink.MAVLink('', 1))

# 计算 payload 开始的位置
header_length = 6 + 1 + 1 + 1 + 1 + 1 + 1 + 3  # STX (1) + Payload Length (1) + Incompatible Flags (1) + Compatible Flags (1) + Sequence (1) + System ID (1) + Component ID (1) + Message ID (3)
payload = packed_message[header_length:]  # 提取 payload

# MAVLink 2 头信息
stx = 0xFD
message_id = command_message.get_msgId()
payload_length = len(payload)

# 创建 MAVLink 2 消息头
header = bytearray()
header.extend(bytearray([stx]))  # STX (Start of Text)
header.extend(payload_length.to_bytes(1, 'little'))  # Payload length
header.extend(bytearray([0]))  # Incompatible flags (设置为 0 或适当的标志)
header.extend(bytearray([0]))  # Compatible flags (设置为 0 或适当的标志)
header.extend(bytearray([0]))  # Sequence number (通常由 MAVLink 库管理)
header.extend(bytearray([255]))  # System ID (广播或特定系统)
header.extend(bytearray([190]))  # Component ID (示例组件 ID)
header.extend(message_id.to_bytes(3, 'little'))  # Message ID (3 字节)

# 计算 CRC
message_with_header = header + payload
crc = crc_calculate(message_with_header, len(message_with_header))

# 获取 CRC_EXTRA 值
crc_extra_list = [50, 124, 137, 0, 237, 217, 104, 119, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0, 0, 0, 214, 159, 220, 168, 24, 23, 170, 144, 67, 115, 39, 246, 185, 104, 237, 244, 222, 212, 9, 254, 230, 28, 28, 132, 221, 232, 11, 153, 41, 39, 214, 223, 141, 33, 15, 3, 100, 24, 239, 238, 30, 200, 183, 0, 130, 0, 148, 21, 0, 52, 124, 0, 0, 0, 20, 0, 152, 143, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 231, 183, 63, 54, 0, 0, 0, 0, 0, 0, 0, 175, 102, 158, 208, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 204, 49, 170, 44, 83, 46, 0]
crc_extra = crc_extra_list[message_id]

# 加入 CRC_EXTRA 计算最终的 CRC
crc = crc_accumulate(crc_extra, crc)

# 将 CRC 转换为字节并转换为十六进制字符串
crc_hex = crc.to_bytes(2, 'little').hex()

# 获取当前微秒时间戳
currentTime = int(time.time() * 1e6)
timestamp = currentTime.to_bytes(8, 'little')[-6:]  # 截取低 6 字节
timestamp_hex = timestamp.hex()

# 将 header 和 payload 转换为十六进制字符串
header_hex = header.hex()
payload_hex = payload.hex()

# 生成签名输入的十六进制字符串形式
signature_input_hex = secreteKey + header_hex + payload_hex + crc_hex + linkid + timestamp_hex

# 将十六进制字符串转换为字节
signature_input_bytes = bytes.fromhex(signature_input_hex)

# 生成签名
hash_result = hashlib.sha256(signature_input_bytes).digest()
signature = hash_result[:6]

# 组合最终的消息
signed_msg = header + payload + bytes.fromhex(crc_hex) + bytes.fromhex(linkid) + timestamp + signature

# 发送消息
try:
    master = mavutil.mavlink_connection('udpout:10.0.2.5:48307')
    master.write(signed_msg)
    print("message sent")
except Exception as e:
    print("error:", str(e))
