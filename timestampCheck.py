from datetime import datetime

# 输入的时间戳
timestamp_str = '2024-09-03 16:43:00.465050000'

# 将时间戳字符串转换为 datetime 对象
dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')

# 将 datetime 对象转换为自 Unix 纪元以来的毫秒数
unix_epoch = datetime(1970, 1, 1)
milliseconds = int((dt - unix_epoch).total_seconds() * 1000)

# 将毫秒数转换为十六进制字符串
hex_stream = format(milliseconds, '013x')

print(hex_stream)
