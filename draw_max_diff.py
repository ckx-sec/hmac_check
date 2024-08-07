import hashlib
import math
from collections import defaultdict
import matplotlib.pyplot as plt
import re

# 读取文件
input_file = './hmac_differences_results.txt'
message_pairs_file = './hmac_message_pairs.txt'


# 解析文件
differences = defaultdict(lambda: defaultdict(int))
with open(input_file, 'r') as f:
    lines = f.readlines()
    current_opad = None
    current_ipad = None
    for line in lines:
        if line.startswith("opad:"):
            parts = line.strip().split(", ")
            current_opad = int(parts[0].split(": ")[1], 16)
            current_ipad = int(parts[1].split(": ")[1], 16)
        elif line.startswith("  Difference:"):
            parts = line.strip().split(", ")
            diff = int(parts[0].split(": ")[1].split(" ")[0])
            count = int(parts[1].split(": ")[1])
            differences[(current_opad, current_ipad)][diff] = count

# 辅助函数：解析消息对
def parse_message(message_str):
    # 使用正则表达式提取消息中的十六进制数字
    hex_str = re.findall(r'[0-9a-fA-F]{2}', message_str)
    return bytes.fromhex(''.join(hex_str))

# 读取消息对
message_pairs = []
with open(message_pairs_file, 'r') as f:
    for line in f:
        parts = line.strip().split(", ")
        message1 = parse_message(parts[0])
        message2 = parse_message(parts[1])
        message_pairs.append((message1, message2))

# 计算每对组合的平均差异
average_differences = {}
max_differences = {}
for (opad_val, ipad_val), diff_counts in differences.items():
    total_diff = sum(diff * count for diff, count in diff_counts.items())
    total_count = sum(diff_counts.values())
    average_diff = total_diff / total_count
    average_differences[(opad_val, ipad_val)] = average_diff
    max_diff = max(diff_counts.values())
    max_differences[(opad_val, ipad_val)] = max_diff

# 按最大的diff数量排序
sorted_combinations = sorted(differences.items(), key=lambda item: max(item[1].values()), reverse=True)

# 选出前 50 个效果最好的组合（按最大diff数量排序）
best_diff_combinations = sorted_combinations[:50]

# # 绘制平均差异统计图
x = range(256)
y = range(256)
# z_avg = [[average_differences.get((opad, ipad), 0) for ipad in y] for opad in x]

# plt.figure(figsize=(12, 10))
# plt.imshow(z_avg, cmap='hot', interpolation='nearest', origin='lower')
# plt.colorbar()
# plt.title('Average Differences for each ipad and opad combination')
# plt.xlabel('ipad values (0x00 to 0xFF)')
# plt.ylabel('opad values (0x00 to 0xFF)')
# plt.show()

# 绘制最大diff数量统计图
z_max = [[max_differences.get((opad, ipad), 0) for ipad in y] for opad in x]

plt.figure(figsize=(12, 10))
plt.imshow(z_max, cmap='hot', interpolation='nearest', origin='lower')
plt.colorbar()
plt.title('Max Diff Counts for each ipad and opad combination')
plt.xlabel('ipad values (0x00 to 0xFF)')
plt.ylabel('opad values (0x00 to 0xFF)')
plt.show()

# 打印前 50 个效果最好的组合（按最大diff数量排序）
print("\nTop 50 best ipad and opad combinations (by max diff count):")
for (opad, ipad), diff_counts in best_diff_combinations:
    max_diff = max(diff_counts.values())
    print(f"opad: {hex(opad)}, ipad: {hex(ipad)}, Max Diff Count: {max_diff}")

# 输出标准组合的效果
standard_opad_val = 0x5c
standard_ipad_val = 0x36
# standard_average_diff = average_differences[(standard_opad_val, standard_ipad_val)]
# print(f"\nStandard combination (ipad = 0x36, opad = 0x5c) Average Difference: {standard_average_diff:.4f}")
# standard_rank_avg_diff = sorted(average_differences.values(), reverse=True).index(standard_average_diff) + 1
# print(f"Standard combination (ipad = 0x36, opad = 0x5c) Average Difference Rank: {standard_rank_avg_diff}")

standard_average_diff = max_differences[(standard_opad_val, standard_ipad_val)]
print(f"\nStandard combination (ipad = 0x36, opad = 0x5c) Average Difference: {standard_average_diff:.4f}")
standard_rank_avg_diff = sorted(max_differences.values(), reverse=True).index(standard_average_diff) + 1
print(f"Standard combination (ipad = 0x36, opad = 0x5c) Average Difference Rank: {standard_rank_avg_diff}")

# # 选出前 50 个效果最差的组合（按平均差异值排序）
# worst_average_diff_combinations = sorted(average_differences.items(), key=lambda item: item[1])[:50]
# print("\nTop 50 worst ipad and opad combinations (by average difference):")
# for (opad, ipad), avg_diff in worst_average_diff_combinations:
#     print(f"opad: {hex(opad)}, ipad: {hex(ipad)}, Average Difference: {avg_diff:.4f}")
