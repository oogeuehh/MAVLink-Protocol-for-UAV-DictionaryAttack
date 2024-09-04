from datetime import datetime
import binascii

# 输入的时间戳
timestamp_str = '2024-09-03 16:43:46.505000'

# 将时间戳字符串转换为 datetime 对象
dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')

# 将 datetime 对象转换为 Unix 时间戳（秒数）
unix_timestamp = int(dt.timestamp())

# 将 Unix 时间戳转换为十六进制字符串
hex_stream = binascii.hexlify(unix_timestamp.to_bytes(8, byteorder='big')).decode()

print(hex_stream)
