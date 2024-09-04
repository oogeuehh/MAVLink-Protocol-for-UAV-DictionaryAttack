from datetime import datetime
import binascii

# 定义时间戳
timestamp_str = "2024-09-03 16:43:46.505000"
timestamp_format = "%Y-%m-%d %H:%M:%S.%f"

# 将时间戳转换为 datetime 对象
dt = datetime.strptime(timestamp_str, timestamp_format)

# 转换为 Unix 时间戳（秒）
unix_timestamp = int(dt.timestamp())

# 转换为十六进制
hex_stream = binascii.hexlify(unix_timestamp.to_bytes((unix_timestamp.bit_length() + 7) // 8, byteorder='big')).decode()

# 输出结果
print(hex_stream)
