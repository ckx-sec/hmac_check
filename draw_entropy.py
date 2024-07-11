import matplotlib.pyplot as plt
import numpy as np

def read_data(filename):
    with open(filename, 'r') as file:
        data = []
        for line in file:
            parts = line.strip().split(', ')
            opad = int(parts[0].split(': ')[1], 16)
            ipad = int(parts[1].split(': ')[1], 16)
            entropy = float(parts[2].split(': ')[1])
            data.append((opad, ipad, entropy))
    return data

def sort_data(data):
    return sorted(data, key=lambda x: x[2], reverse=True)
def plot_heatmap(data):

    entropy_matrix = np.full((256, 256), np.nan) 
    for opad, ipad, entropy in data:
        entropy_matrix[opad, ipad] = entropy

    plt.figure(figsize=(12, 10))
    plt.imshow(entropy_matrix, cmap='viridis', origin='lower')
    plt.colorbar(label='Entropy')
    plt.xlabel('ipad (hex)')
    plt.ylabel('opad (hex)')
    plt.title('HMAC Configuration Entropy Heatmap')
    plt.show()
# def plot_data(data):
#     # 绘制数据点
#     opads, ipads, entropies = zip(*data)
#     plt.scatter(opads, ipads, c=entropies, cmap='viridis')
#     plt.colorbar(label='Entropy')
#     plt.xlabel('opad (hex)')
#     plt.ylabel('ipad (hex)')
#     plt.title('HMAC Configuration Entropies')
#     plt.show()

def find_rank_of_standard_config(data, standard_opad=0x5c, standard_ipad=0x36):
    for index, (opad, ipad, entropy) in enumerate(data, start=1):
        if opad == standard_opad and ipad == standard_ipad:
            return index, entropy
    return None, None 

def main():
    filename = "./hmac_entropy_results.txt"  
    data = read_data(filename)
    sorted_data = sort_data(data)
    
    print("Top 50 configurations by entropy:")
    top_50 = sorted_data[:50]
    for item in top_50:
        print(f"opad: 0x{item[0]:02x}, ipad: 0x{item[1]:02x}, Entropy: {item[2]}")
    
    plot_heatmap(sorted_data)
    
    rank, standard_entropy = find_rank_of_standard_config(sorted_data)
    if standard_entropy is not None:
        print(f"Standard configuration (opad: 0x5c, ipad: 0x36) is ranked #{rank} with Entropy: {standard_entropy}")
    else:
        print("Standard configuration not found in the data.")

if __name__ == "__main__":
    main()
