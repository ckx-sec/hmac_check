## HMAC ipad&opad选择的探讨

陈可欣 202318018670028

老师课上提到了一个问题，就是在hmac中使用0x36和0x5c这两个值的原因，我找到了这篇论文，在文章里，其实也并没有提到为什么这样选择，具体内容如下：

![截屏2024-07-11 15.56.49](../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2015.56.49.png)



于是我打算写个脚本遍历各种0x00-0xff的组合来分析到底效果如何，我可以想到的评价指标有：

1、选择的 `ipad` 和 `opad` 应该保证其异或结果（即 `ipad XOR opad`）能够在位级别上提供显著差异，这有助于保证内部哈希和外部哈希的输入差异性。

2、抗攻击能力，例如抗长度扩展攻击，验证选定的 `ipad` 和 `opad` 组合是否足够抵抗长度扩展攻击。

3、统计分析检查 `ipad` 和 `opad` 异或操作后的输出序列的随机性。



> 为什么使用rust？
>
> 因为sha2库可以实现并行运算，计算3000组hmac只需2-3秒，因为可以调用计算机全部的算力，相同任务python需要5-6小时。

<img src="./%E6%88%AA%E5%B1%8F2024-07-11%2019.06.07.png" alt="截屏2024-07-11 19.06.07" style="zoom:50%;" />

注：不过rust有一个不同（https://docs.rs/hmac/latest/src/hmac/lib.rs.html#1-131）或者（https://github.com/briansmith/ring/blob/main/src/hmac.rs）都是如此，即ipad和opad的设置和论文是相反的。所以我之后都是按照这个来当标准的。

<img src="../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2019.29.24.png" alt="截屏2024-07-11 19.29.24" style="zoom:50%;" />



#### 0x01 实现输入不同ipad/opad的hmac算法

首先，验证自己根据论文写的流程计算出的结果与直接调库一致：

```rust
let opad_val = 0x36;
let ipad_val = 0x5c;
for (msg1, msg2) in message_pairs.iter() {
    let custom_hmac1 = hmac(&key, opad_val, ipad_val, msg1);
    let custom_hmac2 = hmac(&key, opad_val, ipad_val, msg2);

    type HmacSha1 = Hmac<Sha1>;
    let mut mac1 = HmacSha1::new_from_slice(&key).expect("HMAC can take key of any size");
    mac1.update(msg1);
    let result1 = mac1.finalize();
    let official_hmac1 = result1.into_bytes().to_vec();

    let mut mac2 = HmacSha1::new_from_slice(&key).expect("HMAC can take key of any size");
    mac2.update(msg2);
    let result2 = mac2.finalize();
    let official_hmac2 = result2.into_bytes().to_vec();

    println!(
        "Custom HMAC1: {:x?}, Official HMAC1: {:x?}, Equal: {}",
        custom_hmac1, official_hmac1, custom_hmac1 == official_hmac1
    );
    println!(
        "Custom HMAC2: {:x?}, Official HMAC2: {:x?}, Equal: {}",
        custom_hmac2, official_hmac2, custom_hmac2 == official_hmac2
    );
}


fn hmac(key: &[u8], opad_val: u8, ipad_val: u8, message: &[u8]) -> Vec<u8> {
    // Ensure the key is the right length
    let mut key_block = [0x00; 64];
    if key.len() > 64 {
        let mut hasher = Sha1::new();
        hasher.update(key);
        let hashed_key = hasher.finalize();
        key_block[..hashed_key.len()].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    println!("opad_val: {:#x}, ipad_val: {:#x}", opad_val, ipad_val);
    let mut opad = [opad_val; 64];
    let mut ipad = [ipad_val; 64];
    for i in 0..64 {
        opad[i] ^= key_block[i];
        ipad[i] ^= key_block[i];
    }

    let mut hasher = Sha1::new();
    hasher.update(&ipad);
    hasher.update(message);
    let inner_hash = hasher.finalize();

    let mut hasher = Sha1::new();
    hasher.update(&opad);
    hasher.update(&inner_hash);
    hasher.finalize().to_vec()
}

```

![截屏2024-07-11 17.30.47](../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2017.30.47.png)

结果一致，说明自己实现的hmac正确。

#### 0x02 生成随机信息对

为了验证hmac算法的效果，我生成了100000组信息对，每组信息对长度定为101个字节，但只有一个字节不同，如下所示：

```
Message1: [64, 72, 6f, 72, 38, 49, 6c, 5a, 55, 32, 62, 32, 70, 33, 75, 6e, 74, 4d, 70, 73, 73, 61, 73, 45, 52, 52, 54, 6d, 53, 42, 6e, 4a, 7a, 30, 51, 33, 66, 50, 73, 78, 61, 62, 6d, 30, 33, 36, 51, 79, 34, 56, 77, 69, 38, 75, 64, 6b, 46, 57, 39, 7a, 6b, 52, 55, 6b, 48, 7a, 74, 71, 61, 67, 61, 58, 34, 4a, 43, 64, 50, 6b, 4f, 62, 72, 6c, 32, 7a, 77, 53, 63, 38, 4b, 58, 62, 35, 4f, 54, 73, 4d, 55, 30, 55, 33, 33],
Message2: [64, 72, 6f, 72, 38, 49, 6c, 5a, 55, 32, 62, 32, 70, 33, 75, 6e, 74, 4d, 70, 73, 73, 61, 73, 45, 52, 52, 54, 6d, 53, 42, 6e, 4a, 7a, 30, 51, 33, 66, 50, 73, 78, 61, 62, 6d, 30, 33, 36, 51, 79, 53, 56, 77, 69, 38, 75, 64, 6b, 46, 57, 39, 7a, 6b, 52, 55, 6b, 48, 7a, 74, 71, 61, 67, 61, 58, 34, 4a, 43, 64, 50, 6b, 4f, 62, 72, 6c, 32, 7a, 77, 53, 63, 38, 4b, 58, 62, 35, 4f, 54, 73, 4d, 55, 30, 55, 33, 33]
```

算法如下：

```rust
fn generate_random_message(length: usize) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .collect()
}

fn generate_similar_message(message: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut message_list = message.to_vec();
    let idx = rng.gen_range(0..message.len());
    let original_char = message[idx];
    let mut new_char = original_char;
    while new_char == original_char {
        new_char = rng.sample(Alphanumeric) as u8;
    }
    message_list[idx] = new_char;
    message_list
}


let message_length = 101;
let num_message_pairs = 10000;
let message_pairs_file = "hmac_message_pairs.txt";
let mut message_pairs = Vec::new();
let mut f = File::create(message_pairs_file).unwrap();

for _ in 0..num_message_pairs {
    let message1 = generate_random_message(message_length);
    let message2 = generate_similar_message(&message1);
    message_pairs.push((message1.clone(), message2.clone()));
    writeln!(f, "Message1: {:x?}, Message2: {:x?}", message1, message2).unwrap();
}
```

结果存入`hmac_message_pairs.txt`中。

#### 0x03 计算每组hmac字节级的平均差值

```rust
let pads = (0u8..=255)
    .flat_map(|o| (0u8..=255).map(move |i| (o, i)))
    .collect::<Vec<_>>();
let result_map = pads
    .par_iter()
    .map(|(opad_val, ipad_val)| {
        let diff_list = message_pairs
            .par_iter()
            .map(|(msg1, msg2)| {
                let hmac1 = hmac(&key, *opad_val, *ipad_val, msg1);
                let hmac2 = hmac(&key, *opad_val, *ipad_val, msg2);
                let mut diff = 0;
                for i in 0..hmac1.len() {
                    if hmac1[i] != hmac2[1] {
                        diff += 1;
                    }
                }
                diff
            })
            .collect::<Vec<_>>();
        let mut inner_map: HashMap<i32, i32> = HashMap::new();
        for diff in diff_list {
            if let Some(count) = inner_map.get_mut(&diff) {
                *count += 1;
            } else {
                inner_map.insert(diff, 0);
            }
        }
        (opad_val, ipad_val, inner_map)
    })
    .collect::<Vec<_>>();

let output_file = "hmac_differences_results.txt";
let mut f = File::create(output_file).unwrap();
for (opad_val, ipad_val, diff_map) in result_map {
    writeln!(f, "opad: {:#x}, ipad: {:#x}", opad_val, ipad_val).unwrap();
    for (diff, count) in diff_map {
        writeln!(f, "  Difference: {} characters, Count: {}", diff, count).unwrap();
    }
    writeln!(f).unwrap();
}

println!("Results written to {}", output_file);
println!("Message pairs written to {}", message_pairs_file);
```

将结果处理成图：

![截屏2024-07-11 19.54.42](../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2019.54.42.png)



![截屏2024-07-11 19.55.57](../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2019.55.57.png)

#### 0x04 计算hmac字节级的信息熵

```rust
let result_map = pads.par_iter().map(|(opad_val, ipad_val)| {
    let entropies = message_pairs.par_iter().map(|(msg1, _)| {
        let hmac_output =hmac(&key, *opad_val, *ipad_val, msg1);
        calculate_entropy(&hmac_output)
    }).collect::<Vec<_>>();
    let avg_entropy = entropies.iter().sum::<f64>() / entropies.len() as f64;
    (opad_val, ipad_val, avg_entropy)
}).collect::<Vec<_>>();

let output_file = "hmac_entropy_results.txt";
let mut f = File::create(output_file).unwrap();
for (opad_val, ipad_val, entropy) in result_map {
    writeln!(f, "opad: {:#x}, ipad: {:#x}, Entropy: {}", opad_val, ipad_val, entropy).unwrap();
}
println!("Results written to {}", output_file);
```

将结果处理成图：

![截屏2024-07-11 19.51.15](../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2019.51.15.png)

![截屏2024-07-11 19.56.19](../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2019.56.19.png)



#### 0x05 计算每组hmac比特级的平均差值

![截屏2024-07-11 20.21.44](../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2020.21.44.png)

![截屏2024-07-11 20.23.01](../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2020.23.01.png)

#### 0x06 计算hmac比特级的信息熵

![截屏2024-07-11 20.22.23](../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2020.22.23.png)

![截屏2024-07-11 20.22.47](../Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2024-07-11%2020.22.47.png)



### 结论

看到这里，结果貌似说明这组ipad&opad的设置对结果的影响不算很大，使我产生了更大的疑惑。





# hmac_check
