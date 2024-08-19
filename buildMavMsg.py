def build_mavlink_command_long(system_id, component_id, command, sequence, secret_key):
    stx = 0xFD
    payload_len = 33  # Command Long payload length
    incompat_flags = 0
    compat_flags = 0
    
    # 构建MAVLink消息头部
    header = struct.pack('<BBBBBBB', stx, payload_len, incompat_flags, compat_flags, sequence, system_id, component_id)
    
    # Message ID (Command Long message)
    message_id_bytes = struct.pack('<I', 76)[0:3]  # Command Long ID is 76
    
    # 构建有效载荷
    command_id = command
    param1, param2, param3, param4 = 0, 0, 0, 0
    param5, param6, param7 = 0, 0, 0
    target_system = system_id
    target_component = component_id
    confirmation = 0
    
    payload = struct.pack('<ffffffBBH', param1, param2, param3, param4, param5, param6, param7, target_system, target_component, command_id, confirmation)
    
    # 拼接完整消息用于CRC计算
    message = header + message_id_bytes + payload
    
    # 计算CRC
    crc = crc_x25(message)
    
    # 添加CRC到消息
    message += struct.pack('<H', crc)
    
    # 计算签名
    signature = sign_mavlink_message(message, secret_key)
    
    # 添加签名到消息
    message += signature
    
    return message
