rtl_command = mavlink.MAVLink_command_long_message(
    target_system=1,          # 无人机系统ID
    target_component=1,       # 无人机组件ID
    command=mavlink.MAV_CMD_NAV_RETURN_TO_LAUNCH,  # 返航指令
    confirmation=0,           # 确认次数
    param1=0, param2=0, param3=0, param4=0,
    param5=0, param6=0, param7=0
)

# 签名相关的配置
signing_key = b"your_32_byte_key"  # 基站的签名密钥
timestamp = int(mavutil.time_since_boot() * 1000)  # 时间戳

# 签名计算
def compute_signature(key, message, link_id, timestamp):
    # 计算SHA256_48签名
    header = struct.pack('<Q', timestamp) + struct.pack('B', link_id) + message
    hash_value = hashlib.sha256(key + header).digest()[:6]
    return hash_value

# 创建带签名的MAVLink消息
def create_signed_message(message, signing_key, link_id):
    timestamp = int(mavutil.time_since_boot() * 1000)
    signature = compute_signature(signing_key, message.get_msgbuf(), link_id, timestamp)
    message.sign(signing_key, link_id, timestamp)
    return message

# 设置链路ID
link_id = 1

# 创建带签名的返航命令
signed_rtl_command = create_signed_message(rtl_command, signing_key, link_id)

# 发送返航命令
master.mav.send(signed_rtl_command)
