## HMAC ipad&opad选择的探讨

老师课上提到了一个问题，就是在hmac中使用0x36和0x5c这两个值的原因，我找到了这篇论文，在文章里，其实也并没有提到为什么这样选择，具体内容如下：

![截屏2024-07-11 15.56.49](./assets/%E6%88%AA%E5%B1%8F2024-07-11%2015.56.49.png)



于是我打算写个脚本遍历各种0x00-0xff的组合来分析到底效果如何，我可以想到的评价指标有：

1、选择的 `ipad` 和 `opad` 应该保证其异或结果（即 `ipad XOR opad`）能够在位级别上提供显著差异，这有助于保证内部哈希和外部哈希的输入差异性。

2、抗攻击能力，例如抗长度扩展攻击，验证选定的 `ipad` 和 `opad` 组合是否足够抵抗长度扩展攻击。

3、统计分析检查 `ipad` 和 `opad` 异或操作后的输出序列的随机性。



> 为什么使用rust？
>
> 因为sha2库可以实现并行运算，计算3000组hmac只需2-3秒，因为可以调用计算机全部的算力，相同任务python需要5-6小时。

注：不过rust有一个不同（https://docs.rs/hmac/latest/src/hmac/lib.rs.html#1-131）或者（https://github.com/briansmith/ring/blob/main/src/hmac.rs）都是如此，即ipad和opad的设置和论文是相反的。所以我之后都是按照这个来当标准的。

<img src="./assets/%E6%88%AA%E5%B1%8F2024-07-11%2019.29.24.png" alt="截屏2024-07-11 19.29.24" style="zoom:50%;" />



#### 0x01 实现输入不同ipad/opad的hmac算法

首先，验证自己根据论文写的流程计算出的结果与直接调库一致

![截屏2024-07-11 17.30.47](./assets/%E6%88%AA%E5%B1%8F2024-07-11%2017.30.47.png)

结果一致，说明自己实现的hmac正确。

#### 0x02 生成随机信息对

为了验证hmac算法的效果，我生成了100000组信息对，每组信息对长度定为101个字节，但只有一个字节不同，如下所示：

```
Message1: [64, 72, 6f, 72, 38, 49, 6c, 5a, 55, 32, 62, 32, 70, 33, 75, 6e, 74, 4d, 70, 73, 73, 61, 73, 45, 52, 52, 54, 6d, 53, 42, 6e, 4a, 7a, 30, 51, 33, 66, 50, 73, 78, 61, 62, 6d, 30, 33, 36, 51, 79, 34, 56, 77, 69, 38, 75, 64, 6b, 46, 57, 39, 7a, 6b, 52, 55, 6b, 48, 7a, 74, 71, 61, 67, 61, 58, 34, 4a, 43, 64, 50, 6b, 4f, 62, 72, 6c, 32, 7a, 77, 53, 63, 38, 4b, 58, 62, 35, 4f, 54, 73, 4d, 55, 30, 55, 33, 33],
Message2: [64, 72, 6f, 72, 38, 49, 6c, 5a, 55, 32, 62, 32, 70, 33, 75, 6e, 74, 4d, 70, 73, 73, 61, 73, 45, 52, 52, 54, 6d, 53, 42, 6e, 4a, 7a, 30, 51, 33, 66, 50, 73, 78, 61, 62, 6d, 30, 33, 36, 51, 79, 53, 56, 77, 69, 38, 75, 64, 6b, 46, 57, 39, 7a, 6b, 52, 55, 6b, 48, 7a, 74, 71, 61, 67, 61, 58, 34, 4a, 43, 64, 50, 6b, 4f, 62, 72, 6c, 32, 7a, 77, 53, 63, 38, 4b, 58, 62, 35, 4f, 54, 73, 4d, 55, 30, 55, 33, 33]
```


结果存入`hmac_message_pairs.txt`中。

#### 0x03 计算每组hmac字节级的平均差值

将结果处理成图：

![截屏2024-07-11 19.54.42](./assets/%E6%88%AA%E5%B1%8F2024-07-11%2019.54.42.png)


![截屏2024-07-11 19.55.57](./assets/%E6%88%AA%E5%B1%8F2024-07-11%2019.55.57.png)

#### 0x04 计算hmac字节级的信息熵

将结果处理成图：

![截屏2024-07-11 19.51.15](./assets/%E6%88%AA%E5%B1%8F2024-07-11%2019.51.15.png)



![截屏2024-07-11 19.56.19](./assets/%E6%88%AA%E5%B1%8F2024-07-11%2019.56.19.png)



#### 0x05 计算每组hmac比特级的平均差值

![截屏2024-07-11 20.21.44](./assets/%E6%88%AA%E5%B1%8F2024-07-11%2020.21.44.png)



![截屏2024-07-11 20.23.01](./assets/%E6%88%AA%E5%B1%8F2024-07-11%2020.23.01.png)

#### 0x06 计算hmac比特级的信息熵

![截屏2024-07-11 20.22.23](./assets/%E6%88%AA%E5%B1%8F2024-07-11%2020.22.23.png)

![截屏2024-07-11 20.22.47](./assets/%E6%88%AA%E5%B1%8F2024-07-11%2020.22.47.png)



### 结论

看到这里，结果貌似说明这组ipad&opad的设置对结果的影响不算很大，使我产生了更大的疑惑。





