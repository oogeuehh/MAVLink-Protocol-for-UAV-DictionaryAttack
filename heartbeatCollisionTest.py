import csv
from collections import defaultdict

# 初始化存储每个signature的字典
signature_dict = defaultdict(int)

# 假设CSV文件的结构中有一列名为'signature'
csv_file_path = "mavlink_messages.csv"  # 替换为你的CSV文件路径

# 读取CSV文件并统计每个signature出现的次数
with open(csv_file_path, mode='r') as file:
    csv_reader = csv.DictReader(file)
    for row in csv_reader:
        signature = row['signature']  # 读取signature字段
        signature_dict[signature] += 1

# 检查是否有重复的signature
duplicate_signatures = {sig: count for sig, count in signature_dict.items() if count > 1}

# 输出重复的signature
if duplicate_signatures:
    print("发现重复的signature：")
    for sig, count in duplicate_signatures.items():
        print(f"Signature: {sig}, 出现次数: {count}")
else:
    print("没有发现重复的signature。")
