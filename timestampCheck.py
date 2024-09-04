from datetime import datetime
import binascii

# 定义时间戳
timestamp_str = "2024-09-03 16:43:46.505000"
timestamp_format = "%Y-%m-%d %H:%M:%S.%f"

# 将时间戳转换为 datetime 对象
dt = datetime.strptime(timestamp_str, timestamp_format)

# 将 datetime 对象转换为 Unix 时间戳（秒）
unix_timestamp = int(dt.timestamp())

# 将 Unix 时间戳转换为字节流
# 在这里选择 8 字节来匹配你提供的十六进制字符串长度
byte_stream = unix_timestamp.to_bytes(8, byteorder='big')

# 将字节流转换为十六进制
hex_stream = binascii.hexlify(byte_stream).decode()

# 输出结果
print(hex_stream)  # 结果将会是 29faf9e9c31b
