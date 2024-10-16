import json

# 假设你的Wireshark JSON文件路径为'mavlink_capture.json'
json_file_path = 'mavlink_capture.json'

# 打开并加载JSON文件
with open(json_file_path, 'r') as file:
    data = json.load(file)

# 存储所有的signature字段
signatures = []

# 遍历每个数据包
for packet in data:
    # Wireshark JSON文件结构通常包含'_source'字段，里面包含解析的层
    layers = packet.get('_source', {}).get('layers', {})
    
    # 查找MAVLink协议的解析结果，假设signature在这个层中
    mavlink_layer = layers.get('mavlink_proto', {})
    
    # 获取signature字段
    signature = mavlink_layer.get('mavlink_proto.signature', None)
    
    # 如果signature存在，存储下来
    if signature:
        signatures.append(signature)

# 打印所有找到的signature字段
if signatures:
    print("找到的signatures:")
    for sig in signatures:
        print(sig)
else:
    print("没有找到signature字段")
