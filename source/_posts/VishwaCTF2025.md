---
title: VishwaCTF2025
tags: [CTF, RE, WritesUp, Android, Unity]
categories: CTF
---

# VishwaCTF2025

### Hungry Friends

就是一个贪吃蛇游戏，但是运行不了，就算找到了提示所缺的dll，也没用，所以patch没用，只能硬扒代码下来跑，但是一开始解密的数据找不到，然后交叉引用encrypted，就找到了

![image-20250304215107724](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250304215107724.png)

外面显示的是38位，但是进去之后用插件提数据只提到37位qword，

![image-20250304215217263](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250304215217263.png)

然后仿写个脚本出

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// 解密函数
void decrypt(uint64_t *data, size_t data_size, char *output) {
    uint32_t v13 = 0xF96007CB; // 初始密钥
    for (size_t i = 0; i < data_size; i++) {
        uint64_t v11 = data[i]; // 当前数据块
        // 解密逻辑
        output[i] = (char)((v11 - (v13 ^ (1337 * i))) / 0x11);
        // 更新密钥
        v13 ^= (uint32_t)v11; // 确保 v13 是 32 位
    }
    output[data_size] = '\0'; // 字符串结尾
}

int main() {
    // 示例数据（需要解密的数据块）
    uint64_t data[] = {
        0xF9600D81, 0x166C, 0x1DF7, 0x1562, 
        0x083E, 0x0D01, 0x134D, 0x2BE2, 
        0x0591, 0x0BDE, 0x1B0A, 0x0BFD, 
        0x0C9A, 0x8076, 0xF5CC, 0x073B, 
        0x1D84, 0x145F, 0x21BC, 0x092B, 
        0x043D, 0x08AA, 0x1A31, 0x0D90, 
        0x1205, 0xE6F3, 0x0715, 0x138B, 
        0x08DA, 0x1369, 0x1ADE, 0x368C, 
        0x0AE5, 0x05FF, 0x22C0, 0x46B0, 
        0x79C1
    };
    size_t data_size = sizeof(data) / sizeof(data[0]);

    // 分配输出缓冲区
    char *output = (char *)malloc(data_size + 1); // +1 用于字符串结尾
    if (!output) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    // 调用解密函数
    decrypt(data, data_size, output);

    // 输出解密结果
    printf("Decrypted string: %s\n", output);

    // 释放内存
    free(output);
    return 0;
}
```

补个   }

**VishwaCTF{th3r3_4r3_5n4k35_all_4r0und}**



------------------------------------------------------------------------------------------------------------

### Safe Box

一道unity，题目名字也很形象了，就是一个保险箱，输入正确的密码就能开箱，然后里面就是flag

dnSpy打开，发现有混淆，但其实可以用de4dot进行去混淆，然后逻辑就很清晰了

这里就是check，并且还限制了输入密码的次数

```c#

	// Token: 0x0600000F RID: 15 RVA: 0x00002654 File Offset: 0x00000854
	private void method_2()
	{
		if (this.int_4 >= 3)
		{
			this.d.text = "Too Many Wrong Passwords";
			return;
		}
		string b = this.method_28(new string[]
		{
			"ENTER PASSWORD: ",
			this.method_17(this.int_0, 1).ToString(),
			this.method_18(this.int_0, this.int_2).ToString(),
			this.method_20(this.int_0, this.method_19(this.int_3, 1)).ToString(),
			this.method_18(this.method_17(this.method_21(this.int_1, 2), this.method_21(this.int_2, 2)), this.method_19(this.int_3, 5)).ToString(),
			this.method_22(this.int_1, this.method_21(this.int_0, 2)).ToString()
		});
		if (this.d.text == b)
		{
			this.float_0 = 1f;
			I0.J();
			return;
		}
		this.d.color = Color.red;
		this.d.text = "Wrong";
		this.K0();
		Debug.Log(this.int_4);
	}
```

但是在这里直接改if语句并不能起到很好的效果，但是我们在找Assembly-CSharp.dll的时候看到了Mono.Security.dll，mono的通用套路就是**使用dnspy 分析代码+修改IL指令字节码**，然后我们找到重载的这个类

![image-20250305104332037](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250305104332037.png)

完了进行il语句修改，就修改为和下面这个类一样，不等就好

把

![image-20250305104415341](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250305104415341.png)

修改为

![d38cf3518ea2e839eb6d44ef5c30e20d](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/d38cf3518ea2e839eb6d44ef5c30e20d.png)

然后保存，运行程序，随便数一个数字就开箱了

![image-20250305104519129](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250305104519129.png)