from datetime import datetime
import struct

# 获取当前UTC时间
dt = datetime.utcnow()
unix_timestamp = int(dt.timestamp())  # 获取秒数
microseconds = dt.microsecond  # 获取微秒数

# 假设MAVLink时间戳使用4字节秒和4字节微秒
timestamp_bytes = struct.pack('<II', unix_timestamp, microseconds)

# 转换为16进制字符串
hex_timestamp = timestamp_bytes.hex()

print(hex_timestamp)
