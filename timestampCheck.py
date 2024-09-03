import time

# 获取用户输入的时间（Unix 时间戳，单位为秒）
user_input_time = float(input("Enter the current time as Unix timestamp (in seconds): "))

# 将用户输入的时间转换为微秒时间戳
currentTime = int(user_input_time * 1e6)

# 将微秒时间戳转换为 8 字节的字节序列
timestamp = currentTime.to_bytes(8, 'little')[-6:]  # 截取低 6 字节
timestamp_hex = timestamp.hex()

# 打印结果以验证
print("Timestamp (hex):", timestamp_hex)
