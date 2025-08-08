---
title: TGCTF2025 RE
tags: [CTF, RE, WritesUp]
categories: CTF
---

# TGCTF2025 RE

### Base64

考点总结：魔改Base64

题目描述：如题 flag格式为HZNUCTF{}

wp：

拿到附件先查壳，64位的，没有壳

![image-20241222200148991](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20241222200148991.png)

直接ida64分析，拿到伪代码

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *v3; // rbx
  __int64 v4; // rcx
  void *v5; // rbx
  char Destination[16]; // [rsp+20h] [rbp-28h] BYREF

  sub_140001020("Welcome to HZNUCTF!!!\n");
  sub_140001020("Plz input your flag:\n");
  v3 = (char *)malloc(0x2Aui64);
  sub_140001080("%s");
  v4 = -1i64;
  do
    ++v4;
  while ( v3[v4] );
  if ( v4 == 41 )
  {
    strncpy_s(Destination, 9ui64, v3, 8ui64);
    Destination[8] = 0;
    if ( !strcmp(Destination, "HZNUCTF{") )
    {
      v5 = (void *)sub_1400010E0(v3);
      if ( !strcmp((const char *)v5, "AwLdOEVEhIWtajB2CbCWCbTRVsFFC8hirfiXC9gWH9HQayCJVbB8CIF=") )
      {
        sub_140001020("Congratulation!!!");
        free(v5);
        exit(1);
      }
      sub_140001020("wrong_wrong!!!");
      free(v5);
      exit(1);
    }
    sub_140001020("wrong head!!!");
    free(v3);
    exit(1);
  }
  sub_140001020("wrong len!!!");
  free(v3);
  return 0;
}
```

逻辑很简单，输入flag，先检查长度，然后检查头，再接着就是加密了，加密函数就是**sub_1400010E0**函数，点进去看发现是一个魔改的base64，换了表，同时在索引取值的时候也进行了处理，一个类似于凯撒的处理，加24。

![image-20241222200549750](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20241222200549750.png)

加密完了就直接比对结果了

那么在解base64编码的时候，可以先把偏移后的码表输出，然后再用赛博厨子一把梭

```python
table = "GLp/+Wn7uqX8FQ2JDR1c0M6U53sjBwyxglmrCVdSThAfEOvPHaYZNzo4ktK9iebI"
real_table = [0] * 64

for i in range(64):
    num = (i + 24) % 64  # 使用取模运算，确保索引在范围内
    real_table[i] = ord(table[num])

for i in range(64):
    print(chr(real_table[i]), end="")
```

拿到表：**53sjBwyxglmrCVdSThAfEOvPHaYZNzo4ktK9iebIGLp/+Wn7uqX8FQ2JDR1c0M6U**

然后解编码

![image-20241222200733698](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20241222200733698.png)

**HZNUCTF{ad162c-2d94-434d-9222-b65dc76a32}**

-----------------------------------------------------------------------------------------------------------------------------------------------------------

### XTEA

考点总结：魔改XTEA，反调试，伪随机

题目描述：如题，貌似有点misc味? flag格式为HZNUCTF{}

WP:

拿到题目附件，解压缩，里面有个readme.txt、一个.zip和一个.exe，readme里面是压缩包密码，解压缩，是一个exe，和外面那个一样的，查壳，没有壳，64位的

![image-20250104173338545](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250104173338545.png)

ida64打开分析，根据关键字符串跟踪到main函数

![image-20250104173438726](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250104173438726.png)

```c
__int64 sub_140011BE0()
{
  char *v0; // rdi
  __int64 i; // rcx
  __int64 v2; // rax
  __int64 v3; // rdi
  char v5[32]; // [rsp+0h] [rbp-20h] BYREF
  char v6; // [rsp+20h] [rbp+0h] BYREF
  int v7[9]; // [rsp+24h] [rbp+4h] BYREF
  void *Block; // [rsp+48h] [rbp+28h]
  void *v9; // [rsp+68h] [rbp+48h]
  int v10[15]; // [rsp+88h] [rbp+68h] BYREF
  int j; // [rsp+C4h] [rbp+A4h]
  int k; // [rsp+E4h] [rbp+C4h]
  int m; // [rsp+104h] [rbp+E4h]
  int v14; // [rsp+1D4h] [rbp+1B4h]

  v0 = &v6;
  for ( i = 66i64; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  sub_1400113A2(&unk_1400220A7);
  srand(0x7E9u);
  sub_140011181();
  printf("Welcome to HZNUCTF!!!\n");
  printf("Plz input the cipher:\n");
  v7[0] = 0;
  if ( (unsigned int)scanf("%d", v7) == 1 )     // 输入delta
  {
    printf("Plz input the flag:\n");
    Block = malloc(0x21ui64);
    v9 = malloc(0x10ui64);
    if ( (unsigned int)scanf("%s", (const char *)Block) == 1 )// 输入flag
    {
      for ( j = 0; j < 32; j += 4 )
      {
        v14 = *((char *)Block + j + 3) | (*((char *)Block + j + 2) << 8) | (*((char *)Block + j + 1) << 16) | (*((char *)Block + j) << 24);// 字符串处理
        v10[j / 4] = v14;
      }
      sub_1400110B9(v9);
      for ( k = 0; k < 7; ++k )
        sub_140011212((unsigned int)v7[0], &v10[k], &v10[k + 1], v9);// 加密
      for ( m = 0; m < 8; ++m )
      {
        if ( v10[m] != dword_14001D000[m] )     // cmp
        {
          printf("wrong_wrong!!!");
          exit(1);
        }
      }
      printf("Congratulation!!!");
      free(Block);
      free(v9);
      v2 = 0i64;
    }
    else
    {
      printf("Invalid input.\n");
      free(Block);
      free(v9);
      v2 = 1i64;
    }
  }
  else
  {
    printf("Invalid input.\n");
    v2 = 1i64;
  }
  v3 = v2;
  sub_14001133E(v5, &unk_14001AD40);
  return v3;
}
```

根据代码逻辑对一些函数进行重命名，同时对一些函数功能进行注释

整体逻辑就是先输入一个密码，这个密码也就是前面给的压缩包的解压密码，转成十六进制是0x9E3779B9，很明显就是xtea加密的delta

![image-20250104173837132](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250104173837132.png)

首先是加密所用到的key，在sub_1400110B9函数中进行初始化

![image-20250104174038200](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250104174038200.png)

可以看到就是一个伪随机，但是种子是在函数的最开始

![image-20250104175434787](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250104175434787.png)

那么就可以根据已知的种子获取key的值，或者动态调试拿key，但是这里有一个反调试，在sub_140011181函数里

![image-20250104175419437](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250104175419437.png)

检测到调式的话伪随机的种子就会改变

导致key也不一样，想通过动调拿key简单绕一下就可以了

下面是获取key的脚本

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
int main() {
    srand(0x7e8u);
    for (int i = 0; i < 4; i++) {
        printf("%d\n", rand());
    }

    return 0;
}
```

key

> 6648
> 4542
> 2449
> 13336

初始完了key，这里有一个for循环，就是处理输入的32位的明文，分成八组进行加密

![image-20250104175909142](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250104175909142.png)

然后是加密函数，通过查看sub_140011212函数可知是一个没有进行魔改的xtea加密，但是在明文传进去的时候做了一些改变，不是和标准的xtea以01 23 45这样的组合进行加密，而是01 12 23这样的组合，那么在解密的时候需要倒着来进行解密

以下就是解密脚本

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define delta 0x9E3779B9

void decrypt(uint32_t* enc, uint32_t* key) {
    unsigned int sum, i;
    uint32_t v1, v2;
    v1 = enc[0];
    v2 = enc[1];
    sum = 32 * -delta;

    for (i = 0; i < 32; i++) {
        v2 -= (key[(sum >> 11) & 3] + sum) ^ (v1 + ((v1 >> 5) ^ (16 * v1)));
        sum += delta;
        v1 -= (key[sum & 3] + sum) ^ (v2 + ((v2 >> 5) ^ (16 * v2)));
    }

    enc[0] = v1;
    enc[1] = v2;
}

void print_as_big_endian(uint32_t value) {
    // 将每个字节打印出来，按大端序排列
    for (int i = 3; i >= 0; i--) {  // 从最高字节开始输出
        printf("%c", (unsigned char)((value >> (i * 8)) & 0xFF));  // 提取字节并打印
    }
}

int main() {
    uint32_t key[4];  
    key[0] = 6648;
    key[1] = 4542;
    key[2] = 2449;
    key[3] = 13336;

    uint32_t enc[8];
    enc[0] = 0x8ccb2324;
    enc[1] = 0x09a7741a;
    enc[2] = 0xfb3c678d;
    enc[3] = 0xf6083a79;
    enc[4] = 0xf1cc241b;
    enc[5] = 0x39fa59f2;
    enc[6] = 0xf2abe1cc;
    enc[7] = 0x17189f72;

    for (int index = 6; index >= 0; index--) {  
        decrypt(&enc[index], key);
    }

    for (int i = 0; i < 8; i++) {
        print_as_big_endian(enc[i]);  // 打印按大端序的值
    }

    printf("\n");
    puts((char *)enc);  

    return 0;
}
```

**HZNUCTF{ae6-9f57-4b74-b423-98eb}**



-----------------------------------------------------------------------------------------------------------------------------------------------------------

### exchange

考点总结：PE文件格式，UPX壳，自定义加密，魔改DES

题目描述：嘶，为什么不能运行呢，但好像也不影响？ flag格式为HZNUCTF{}

WP：

根据题目描述，把文件位数改成64bit，就可以正常运行程序了。用die可以查出这是64位的文件，但是用010打开来看不符合64位文件的格式

![image-20250301115519561](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250301115519561.png)

![image-20250209134613624](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250209134613624.png)

把0B 01改成0B 02。ida64打开分析，根据关键字符串定位到main函数

然后依据逻辑对一些变量和函数名进行重命名

```c
__int64 sub_140012F90()
{
  char *v0; // rdi
  __int64 i; // rcx
  char v3[32]; // [rsp+0h] [rbp-20h] BYREF
  char v4; // [rsp+20h] [rbp+0h] BYREF
  char *flag; // [rsp+28h] [rbp+8h]
  char Destination[44]; // [rsp+48h] [rbp+28h] BYREF
  char Str1[36]; // [rsp+74h] [rbp+54h] BYREF
  char *v8; // [rsp+98h] [rbp+78h]
  char v9[100]; // [rsp+C0h] [rbp+A0h] BYREF
  int j; // [rsp+124h] [rbp+104h]
  unsigned __int8 v11; // [rsp+144h] [rbp+124h]
  unsigned __int8 v12; // [rsp+164h] [rbp+144h]
  char v13[32]; // [rsp+184h] [rbp+164h] BYREF
  char v14[32]; // [rsp+1A4h] [rbp+184h] BYREF
  char v15; // [rsp+1C4h] [rbp+1A4h]

  v0 = &v4;
  for ( i = 114i64; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  sub_1400113CA(&unk_1400260A6);
  flag = (char *)malloc(0x2Aui64);
  printf("Welcome to HZNUCTF!!!\n");
  printf("Plz input the flag:\n");
  scanf(&aS, flag);
  strncpy_s(Destination, 9ui64, flag, 8ui64);
  strncpy_s(Str1, 2ui64, flag + 40, 1ui64);
  if ( !j_strcmp(Destination, "HZNUCTF{") && !j_strcmp(Str1, "}") )
  {
    v8 = (char *)malloc(0x24ui64);
    strncpy_s(v8, 0x24ui64, flag + 8, 0x20ui64);
    memset(v9, 0, 0x41ui64);
    for ( j = 0; j < 32; j += 2 )
    {
      v11 = 0;
      v12 = 0;
      memset(v13, 0, 5ui64);
      memset(v14, 0, 3ui64);
      v11 = v8[j];
      sub_140011393(v13, "%x", v11);
      v12 = v8[j + 1];
      sub_140011393(v14, "%x", v12);
      j_strcat(v13, v14);
      v15 = v13[1];
      v13[1] = v13[2];
      v13[2] = v15;
      j_strcat(v9, v13);
    }
    sub_1400113ED(v9, Destination);
    printf("Congratulation!!!\n");
    free(v8);
  }
  free(flag);
  sub_14001135C(v3, &unk_14001D390);
  return 0i64;
}
```

程序的整体逻辑就是先对输入的flag进行格式检查，是否满足HZNUCTF{}，然后对大括号内的内容进行加密处理，先把每一个字符转成十六进制，然后将这些十六进制转为字符串，并将每四个字符中的两个进行交换位置，最后传入sub_1400113ED函数进行魔改的DES加密，这里可以利用插件识别出是DES加密

![image-20250209141110123](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250209141110123.png)

并且最终check的密文就在此函数中

```c
__int64 __fastcall sub_140017F30(int a1, int a2)
{
  char *v2; // rdi
  __int64 i; // rcx
  int v4; // edx
  char v6[32]; // [rsp+0h] [rbp-30h] BYREF
  char v7; // [rsp+30h] [rbp+0h] BYREF
  char Src[96]; // [rsp+40h] [rbp+10h] BYREF
  char v9[64]; // [rsp+A0h] [rbp+70h] BYREF
  int j; // [rsp+F4h] [rbp+C4h]

  v2 = &v7;
  for ( i = 58i64; i; --i )
  {
    *(_DWORD *)v2 = -858993460;
    v2 += 4;
  }
  sub_1400113CA(&unk_1400260A6);
  j_memcpy(v9, Src, sizeof(v9));
  LOBYTE(v4) = 8;
  sub_1400113B6(a2, v4, a1, (unsigned int)Src, 8);
  for ( j = 0; j < 64; ++j )
  {
    if ( (unsigned __int8)Src[j] != enc[j] )
    {
      printf("wrong_wrong!!!\n");
      exit(1);
    }
  }
  return sub_14001135C(v6, &unk_14001D1F0);
}
```

![image-20250209141513061](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250209141513061.png)

标准的totrot是1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28，在网上找个脚本，把这个修改一下就可以正常解密了。这里DES解密的密钥是flag头**HZNUCTF{**，

```c
#include <string.h>
#include <stdio.h>

#define EN0 0   /* MODE == encrypt */
#define DE1 1   /* MODE == decrypt */

typedef struct 
{
  unsigned long ek[32];
  unsigned long dk[32];
} des_ctx;

static unsigned long SP1[64] = {
    0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
    0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
    0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
    0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
    0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
    0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
    0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
    0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
    0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
    0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
    0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
    0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
    0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
    0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
    0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
    0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L };

static unsigned long SP2[64] = {
    0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
    0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
    0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
    0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
    0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
    0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
    0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
    0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
    0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
    0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
    0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
    0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
    0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
    0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
    0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
    0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L };

static unsigned long SP3[64] = {
    0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
    0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
    0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
    0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
    0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
    0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
    0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
    0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
    0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
    0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
    0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
    0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
    0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
    0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
    0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
    0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L };

static unsigned long SP4[64] = {
    0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
    0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
    0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
    0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
    0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
    0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
    0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
    0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
    0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
    0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
    0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
    0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
    0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
    0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
    0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
    0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L };

static unsigned long SP5[64] = {
    0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
    0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
    0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
    0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
    0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
    0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
    0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
    0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
    0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
    0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
    0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
    0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
    0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
    0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
    0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
    0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L };

static unsigned long SP6[64] = {
    0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
    0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
    0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
    0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
    0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
    0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
    0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
    0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
    0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
    0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
    0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
    0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
    0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
    0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
    0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
    0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L };

static unsigned long SP7[64] = {
    0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
    0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
    0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
    0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
    0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
    0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
    0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
    0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
    0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
    0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
    0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
    0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
    0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
    0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
    0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
    0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L };

static unsigned long SP8[64] = {
    0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
    0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
    0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
    0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
    0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
    0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
    0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
    0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
    0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
    0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
    0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
    0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
    0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
    0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
    0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
    0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L };

#define   CRCSEED 0x7529

static void scrunch(unsigned char *, unsigned long *);
static void unscrun(unsigned long *, unsigned char *);
static void desfunc(unsigned long *, unsigned long *);
static void cookey(unsigned long *);
void usekey(register unsigned long *from);

static unsigned long KnL[32] = { 0L };
//static unsigned long KnR[32] = { 0L };
//static unsigned long Kn3[32] = { 0L };
//static unsigned char Df_Key[24] = {
//  0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
//  0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
//  0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67 };

static unsigned short bytebit[8]    = {
    0200, 0100, 040, 020, 010, 04, 02, 01 };

static unsigned long bigbyte[24] = {
    0x800000L,  0x400000L,  0x200000L,  0x100000L,
    0x80000L,   0x40000L,   0x20000L,   0x10000L,
    0x8000L,    0x4000L,    0x2000L,    0x1000L,
    0x800L,     0x400L,     0x200L,     0x100L,
    0x80L,      0x40L,      0x20L,      0x10L,
    0x8L,       0x4L,       0x2L,       0x1L    };

/* Use the key schedule specified in the Standard (ANSI X3.92-1981). */ 

static unsigned char pc1[56] = {
    56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
     9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
    13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3 };

static unsigned char totrot[16] = {                                                 //魔改的地方
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

static unsigned char pc2[48] = {
    13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31 };

void deskey(unsigned char *key,short edf)   /* Thanks to James Gillogly & Phil Karn! */
{
    register int i, j, l, m, n;
    unsigned char pc1m[56], pcr[56];
    unsigned long kn[32];

    for ( j = 0; j < 56; j++ ) 
    {
        l = pc1[j];
        m = l & 07;
        pc1m[j] = (key[l >> 3] & bytebit[m]) ? 1 : 0;
    }
    for( i = 0; i < 16; i++ )
    {
        if( edf == DE1 ) m = (15 - i) << 1;
        else m = i << 1;
        n = m + 1;
        kn[m] = kn[n] = 0L;
        for( j = 0; j < 28; j++ )
        {
            l = j + totrot[i];
            if( l < 28 ) pcr[j] = pc1m[l];
            else pcr[j] = pc1m[l - 28];
        }
        for( j = 28; j < 56; j++ ) 
        {
            l = j + totrot[i];
            if( l < 56 ) pcr[j] = pc1m[l];
            else pcr[j] = pc1m[l - 28];
        }
        for( j = 0; j < 24; j++ ) 
        {
            if( pcr[pc2[j]] ) kn[m] |= bigbyte[j];
            if( pcr[pc2[j+24]] ) kn[n] |= bigbyte[j];
        }
    }
    cookey(kn);
    return;
}

static void cookey(register unsigned long *raw1)
{
    register unsigned long *cook, *raw0;
    unsigned long dough[32];
    register int i;

    cook = dough;
    for( i = 0; i < 16; i++, raw1++ ) 
    {
        raw0 = raw1++;
        *cook    = (*raw0 & 0x00fc0000L) << 6;
        *cook   |= (*raw0 & 0x00000fc0L) << 10;
        *cook   |= (*raw1 & 0x00fc0000L) >> 10;
        *cook++ |= (*raw1 & 0x00000fc0L) >> 6;
        *cook    = (*raw0 & 0x0003f000L) << 12;
        *cook   |= (*raw0 & 0x0000003fL) << 16;
        *cook   |= (*raw1 & 0x0003f000L) >> 4;
        *cook++ |= (*raw1 & 0x0000003fL);
    }
    usekey(dough);
    return;
}

void cpkey(register unsigned long *into)
{
    register unsigned long *from, *endp;

    from = KnL, endp = &KnL[32];
    while( from < endp ) *into++ = *from++;
    return;
}

void usekey(register unsigned long *from)
{
    register unsigned long *to, *endp;

    to = KnL, endp = &KnL[32];
    while( to < endp ) *to++ = *from++;
    return;
}

void des(unsigned char *inblock, unsigned char *outblock)
{
    unsigned long work[2];

    scrunch(inblock, work);
    desfunc(work, KnL);
    unscrun(work, outblock);
    return;
}

static void scrunch(register unsigned char *outof, register unsigned long *into)
{
    *into    = (*outof++ & 0xffL) << 24;
    *into   |= (*outof++ & 0xffL) << 16;
    *into   |= (*outof++ & 0xffL) << 8;
    *into++ |= (*outof++ & 0xffL);
    *into    = (*outof++ & 0xffL) << 24;
    *into   |= (*outof++ & 0xffL) << 16;
    *into   |= (*outof++ & 0xffL) << 8;
    *into   |= (*outof   & 0xffL);
    return;
}

static void unscrun(register unsigned long *outof, register unsigned char *into)
{
    *into++ = (unsigned char)((*outof >> 24) & 0xffL);
    *into++ = (unsigned char)((*outof >> 16) & 0xffL);
    *into++ = (unsigned char)((*outof >>  8) & 0xffL);
    *into++ = (unsigned char)(*outof++   & 0xffL);
    *into++ = (unsigned char)((*outof >> 24) & 0xffL);
    *into++ = (unsigned char)((*outof >> 16) & 0xffL);
    *into++ = (unsigned char)((*outof >>  8) & 0xffL);
    *into   =  (unsigned char)(*outof    & 0xffL);
    return;
}

static void desfunc(register unsigned long *block,register unsigned long *keys)
{
    register unsigned long fval, work, right, leftt;
    register int round;
    
    leftt = block[0];
    right = block[1];
    work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
    right ^= work;
    leftt ^= (work << 4);
    work = ((leftt >> 16) ^ right) & 0x0000ffffL;
    right ^= work;
    leftt ^= (work << 16);
    work = ((right >> 2) ^ leftt) & 0x33333333L;
    leftt ^= work;
    right ^= (work << 2);
    work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
    leftt ^= work;
    right ^= (work << 8);
    right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL;
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = ((leftt << 1) | ((leftt >> 31) & 1L)) & 0xffffffffL;
    
    for( round = 0; round < 8; round++ ) 
    {
        work  = (right << 28) | (right >> 4);
        work ^= *keys++;
        fval  = SP7[ work        & 0x3fL];
        fval |= SP5[(work >>  8) & 0x3fL];
        fval |= SP3[(work >> 16) & 0x3fL];
        fval |= SP1[(work >> 24) & 0x3fL];
        work  = right ^ *keys++;
        fval |= SP8[ work        & 0x3fL];
        fval |= SP6[(work >>  8) & 0x3fL];
        fval |= SP4[(work >> 16) & 0x3fL];
        fval |= SP2[(work >> 24) & 0x3fL];
        leftt ^= fval;
        work  = (leftt << 28) | (leftt >> 4);
        work ^= *keys++;
        fval  = SP7[ work        & 0x3fL];
        fval |= SP5[(work >>  8) & 0x3fL];
        fval |= SP3[(work >> 16) & 0x3fL];
        fval |= SP1[(work >> 24) & 0x3fL];
        work  = leftt ^ *keys++;
        fval |= SP8[ work        & 0x3fL];
        fval |= SP6[(work >>  8) & 0x3fL];
        fval |= SP4[(work >> 16) & 0x3fL];
        fval |= SP2[(work >> 24) & 0x3fL];
        right ^= fval;
    }
        
    right = (right << 31) | (right >> 1);
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = (leftt << 31) | (leftt >> 1);
    work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
    right ^= work;
    leftt ^= (work << 8);
    work = ((leftt >> 2) ^ right) & 0x33333333L;
    right ^= work;
    leftt ^= (work << 2);
    work = ((right >> 16) ^ leftt) & 0x0000ffffL;
    leftt ^= work;
    right ^= (work << 16);
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
    leftt ^= work;
    right ^= (work << 4);
    *block++ = right;
    *block = leftt;
    return;
}

/* Validation sets:
 *
 * Single-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef
 * Plain  : 0123 4567 89ab cde7
 * Cipher : c957 4425 6a5e d31d
 *****************************************************************/

void des_key(des_ctx *dc, unsigned char *key)
{
    deskey(key,EN0);
    cpkey(dc->ek);
    deskey(key,DE1);
    cpkey(dc->dk);
}

/*Encrypt several blocks in ECB mode. Caller is responsible for short blocks. */
void des_enc(des_ctx *dc, unsigned char *data, int blocks)
{
    unsigned long work[2];
    int i;
    unsigned char *cp;
    cp=data;
    for(i=0;i<blocks;i++)
    {
        scrunch(cp,work);
        desfunc(work,dc->ek);
        unscrun(work,cp);
        cp+=8;
    }
}

void des_dec(des_ctx *dc, unsigned char *data, int blocks)
{
    unsigned long work[2];
    int i;
    unsigned char *cp;
    cp=data;

    for(i=0;i<blocks;i++)
    {
        scrunch(cp,work);
        desfunc(work,dc->dk);
        unscrun(work,cp);
        cp+=8;
    }
}



int des_encrypt(const unsigned char* Key,const unsigned char KeyLen,const unsigned char* PlainContent,unsigned char* CipherContent,const int BlockCount)
{
    des_ctx dc;
    unsigned char  keyEn[8];
    unsigned char  keyDe[8];
    
    if((BlockCount == 0) || (Key == NULL) || (CipherContent == NULL) || (PlainContent == NULL))
    {
        return -1;
    }

    if((KeyLen != 8) && (KeyLen != 16))
    {
        return -1;
    }

    memcpy(CipherContent, PlainContent,BlockCount*8);   

    switch (KeyLen)
    {
    case 8:    // DES
        memcpy(keyEn,Key,8);               //keyEn
        des_key(&dc, keyEn);
        des_enc(&dc, CipherContent, BlockCount);
        break;
    case 16:    // 3DES
        memcpy(keyEn,Key,8);               //keyEn
        memcpy(keyDe, Key+8, 8);      //keyDe
        des_key(&dc, keyEn);
        des_enc(&dc, CipherContent, BlockCount);
        
        des_key(&dc, keyDe);
        des_dec(&dc, CipherContent, BlockCount);

        des_key(&dc, keyEn);
        des_enc(&dc, CipherContent, BlockCount);
        break;

        default:
            return -1;          
    }
    return 0;   
}


int des_decrypt(const unsigned char* Key,const unsigned char KeyLen,const unsigned char* CipherContent,unsigned char* PlainContent,const int BlockCount)
{
    des_ctx dc;
    unsigned char keyEn[8];
    unsigned char keyDe[8];
    
    if((BlockCount == 0) || (Key == NULL) || (CipherContent == NULL) || (PlainContent == NULL))
    {
        return -1;
    }

    if((KeyLen != 8) && (KeyLen != 16))
    {
        return -1;
    }

    memcpy(PlainContent,CipherContent,BlockCount*8);    
    
    switch (KeyLen)
    {
    case 8:    // DES
        memcpy(keyEn,Key,8);               //keyEn
        des_key(&dc, keyEn);
        des_dec(&dc, PlainContent, BlockCount);
        break;
    case 16:
        memcpy(keyEn,Key,8);               //keyEn
        memcpy(keyDe, Key+8, 8);        //keyDe
        des_key(&dc, keyEn);
        des_dec(&dc, PlainContent, BlockCount);

        des_key(&dc, keyDe);
        des_enc(&dc, PlainContent, BlockCount);

        des_key(&dc, keyEn);
        des_dec(&dc, PlainContent, BlockCount);             
        break;
    default:
        return -1;          
    }
    return 0;
}

int main()
{
    unsigned char i;
    unsigned char plain[64];
    unsigned char cipher[64]; 
    unsigned char key[16] = {0x48, 0x5a, 0x4e, 0x55, 0x43, 0x54, 0x46, 0x7b};
    unsigned char data[64];
    char string[] = "333936147332632923d96353321d3345636826d26314621d3349330463126348";
    for (int i = 0; i < 64; i++) {
        data[i] = string[i];
    }
    memcpy((void*)plain, data, 64);
    des_encrypt(key, 8, plain, cipher,8);      
    
    if(des_decrypt(key, 8, cipher, plain, 8) == 0x0) {
        printf("sc_des plain data: \n");
        for(i = 0; i < 64; i++) {
            printf("%c",plain[i]);
        }
        printf(("\n"));       
    }
    else {
        printf("sc_des failed \n");
    }
    return 0;
}
```

拿到DES加密之前的数据

**333936147332632923d96353321d3345636826d26314621d3349330463126348**

再写个脚本每四位的中间两位交换一下位置，就可以拿到flag了

```python
enc = "333936147332632923d96353321d3345636826d26314621d3349330463126348"
enc_list = list(enc)

# 交换字符
for i in range(1, len(enc_list), 4):
    if i + 1 < len(enc_list):
        enc_list[i], enc_list[i + 1] = enc_list[i + 1], enc_list[i]

processed_str = "".join(enc_list)

print("HZNUCTF{", end="")
# 每两位转成字符并输出
for i in range(0, len(processed_str), 2):
    hex_str = processed_str[i:i+2]
    print(chr(int(hex_str, 16)), end="")
print("}")
```

**HZNUCTF{391ds2b9-9e31-45f8-ba4a-4904a2d8}**

后记：有的师傅非预期了，预期解如上，但是我在出题的时候源码中忘记删掉3DES的代码了，导致可以直接patch调用3DES中的解密函数，直接解密了...

-----------------------------------------------------------------------------------------------------------------------------------------------

### conforand

考点总结：ollvm混淆，魔改RC4，伪随机数爆破

题目描述：简直辣眼睛... flag格式为HZNUCTF{}

WP：

ida打开，混淆非常严重，但是函数名都没做任何混淆，可以用插件D-810进行一定程度的去混淆

下面是去混淆后函数部分截图，同时根据逻辑对函数名和变量名进行了重命名

main函数

![image-20250213125821396](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213125821396.png)

![image-20250213130010978](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130010978.png)

init函数，sub_5s5s5s函数，这两个函数就是对rc4的密钥进行初始化以及伪随机初始化

![image-20250213125900403](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213125900403.png)

![image-20250213125916874](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213125916874.png)

![image-20250213125925981](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213125925981.png)

rc4函数

![image-20250213130057732](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130057732.png)

![image-20250213130126684](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130126684.png)

![image-20250213130134256](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130134256.png)

![image-20250213130142272](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130142272.png)

![image-20250213130149747](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130149747.png)

![image-20250213130158890](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130158890.png)

init_sbox函数

![image-20250213130251422](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130251422.png)

![image-20250213130312758](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130312758.png)

![image-20250213130319813](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130319813.png)

![image-20250213130333765](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130333765.png)

rc4魔改了三个地方，一个是sbox初始化时，密钥形成密钥流的时候异或了伪随机生成的一个数，然后在rc4加密函数中的swap改成了

![image-20250213130447399](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250213130447399.png)

以及加密的轮数是257

那么就可以写解密爆破脚本了，根据附件中的output.txt

```c
#include <stdio.h>
#include <time.h>
#include <stdlib.h>  
#include <string.h>

int init(unsigned char* s, char* key, unsigned long Len_k)
{
    
	int i = 0, j = 0;
	unsigned k[258] = { 0 };
	unsigned char tmp = 0;
	for (i = 0; i < 257; i++) {
		s[i] = i;
		k[i] = key[i % Len_k];
	}
	for (i = 0; i < 257; i++) {
		j = (j + s[i] + k[i]) % 257;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
	return 0; 
}


int rc4(unsigned char* Data, unsigned long Len_D, char* key, unsigned long Len_k) 
{
	
	unsigned char s[258];
	init(s, key, Len_k);
	int i = 0, j = 0, t = 0;
	unsigned long k = 0;
	unsigned char tmp;
	
	for (k = 0; k < Len_D; k++) {
		i = (i + 1) % 257;
		j = (j + s[i]) % 257;
		s[i] = s[j];
		s[j] = s[i];
		t = (s[i] + s[j]) % 257;
		Data[k] = Data[k] ^ s[t];
	}
	return 0; 
}

int main() {
    char key[] = "JustDoIt!";
    for (int rand_num = 0; rand_num <= 365; rand_num++) {
        unsigned char qw[] = {0x83, 0x1e, 0x9c, 0x48, 0x7a, 0xfa, 0xe8, 0x88, 0x36, 0xd5, 
                              0x0a, 0x08, 0xf6, 0xa7, 0x70, 0x0f, 0xfd, 0x67, 0xdd, 0xd4, 
                              0x3c, 0xa7, 0xed, 0x8d, 0x51, 0x10, 0xce, 0x6a, 0x9e, 0x56, 
                              0x57, 0x83, 0x56, 0xe7, 0x67, 0x9a, 0x67, 0x22, 0x24, 0x6e, 
                              0xcd, 0x2f};
        strcpy(key, "JustDoIt!");
        for (int j = 0; j < 9; j++) {
            key[j] ^= rand_num;
        }

        unsigned long key_len = sizeof(key) - 1;
        rc4(qw, sizeof(qw), key, key_len);
        if (qw[0] == 'H' && qw[1] == 'Z' && qw[2] == 'N' && qw[3] == 'U') {
            for (int ii = 0; ii < 42; ii++) {
                printf("%c", qw[ii]);
            }
            printf("\nrand_num: %d", rand_num);
            return 0;
        }
    }

    return 0;
}
```

**HZNUCTF{489b88-1305-411e-b1f4-88a3070a73}**
rand_num: 56

-------------------------------------------------------------------------------------------------------------



### 水果忍者

考点总结：unity游戏逆向，AES加密

题目描述：Just for fun...(貌似有些bug？但好像不影响...) flag格式为HZNUCTF{}

WP：

签到题，找到Assembly-CSharp.dll，然后用dnSpy打开，

![image-20250226102346685](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250226102346685.png)

找到GameManger这个类，可以看到代码没有任何混淆，分析下逻辑，就是切水果分数达到999999999就会弹flag，flag是由程序中设定好的密文经AES CBC模式进行解密得到的。key和iv都可以直接获取

```c#
// Token: 0x0600001C RID: 28 RVA: 0x00002474 File Offset: 0x00000674
	public void IncreaseScore(int points)
	{
		this.score += points;
		this.scoreText.text = this.score.ToString();
		if (this.score >= 999999999)
		{
			byte[] cipherText = this.ConvertHexStringToByteArray(GameManager.encryptedHexData);
			string text = this.Decrypt(cipherText, GameManager.encryptionKey, GameManager.iv);
			if (this.decryptedTextDisplay != null)
			{
				this.decryptedTextDisplay.text = text;
			}
		}
		else if (this.decryptedTextDisplay != null)
		{
			this.decryptedTextDisplay.text = "";
		}
		float num = PlayerPrefs.GetFloat("hiscore", 0f);
		if ((float)this.score > num)
		{
			num = (float)this.score;
			PlayerPrefs.SetFloat("hiscore", num);
		}
	}
```

```c#
	// Token: 0x0600001E RID: 30 RVA: 0x0000257C File Offset: 0x0000077C
	private string Decrypt(byte[] cipherText, string key, string iv)
	{
		string result;
		using (Aes aes = Aes.Create())
		{
			aes.Key = Encoding.UTF8.GetBytes(key);
			aes.IV = Encoding.UTF8.GetBytes(iv);
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.PKCS7;
			ICryptoTransform transform = aes.CreateDecryptor(aes.Key, aes.IV);
			using (MemoryStream memoryStream = new MemoryStream(cipherText))
			{
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read))
				{
					using (StreamReader streamReader = new StreamReader(cryptoStream))
					{
						result = streamReader.ReadToEnd();
					}
				}
			}
		}
		return result;
	}
```

![image-20250226102715355](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250226102715355.png)

赛博厨子一把梭

![image-20250226102816918](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250226102816918.png)

**HZNUCTF{de20-70dd-4e62-b8d0-06e}**

------------------------------------------------------------------------------------------------------------------------------

### 蛇年的本命语言

考点总结：python逆向，z3，自定义加密，变量名混淆

题目描述：如题...flag的格式为HZNUCTF{}

WP：

附件是个python的exe，运行的时候可能会提示缺少python38.dll，在同级目录放一个就好了

用pyinstxtractor解包，然后找到output.pyc，直接用uncompyle6反编译，得到伪代码

```python
# uncompyle6 version 3.9.2
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.10 (tags/v3.8.10:3d8993a, May  3 2021, 11:48:03) [MSC v.1928 64 bit (AMD64)]
# Embedded file name: output.py
from collections import Counter
print("Welcome to HZNUCTF!!!")
print("Plz input the flag:")
ooo0oOoooOOO0 = input()
oOO0OoOoo000 = Counter(ooo0oOoooOOO0)
O0o00 = "".join((str(oOO0OoOoo000[oOooo0OOO]) for oOooo0OOO in ))
print("ans1: ", end="")
print(O0o00)
if O0o00 != "111111116257645365477364777645752361":
    print("wrong_wrong!!!")
    exit(1)
iiIII = ""
for oOooo0OOO in ooo0oOoooOOO0:
    if oOO0OoOoo000[oOooo0OOO] > 0:
        iiIII += oOooo0OOO + str(oOO0OoOoo000[oOooo0OOO])
        oOO0OoOoo000[oOooo0OOO] = 0
    else:
        i11i1Iii1I1 = [ord(oOooo0OOO) for oOooo0OOO in iiIII]
        ii1iIi1i11i = [
         7 * i11i1Iii1I1[0] == 504,
         9 * i11i1Iii1I1[0] - 5 * i11i1Iii1I1[1] == 403,
         2 * i11i1Iii1I1[0] - 5 * i11i1Iii1I1[1] + 10 * i11i1Iii1I1[2] == 799,
         3 * i11i1Iii1I1[0] + 8 * i11i1Iii1I1[1] + 15 * i11i1Iii1I1[2] + 20 * i11i1Iii1I1[3] == 2938,
         5 * i11i1Iii1I1[0] + 15 * i11i1Iii1I1[1] + 20 * i11i1Iii1I1[2] - 19 * i11i1Iii1I1[3] + 1 * i11i1Iii1I1[4] == 2042,
         7 * i11i1Iii1I1[0] + 1 * i11i1Iii1I1[1] + 9 * i11i1Iii1I1[2] - 11 * i11i1Iii1I1[3] + 2 * i11i1Iii1I1[4] + 5 * i11i1Iii1I1[5] == 1225,
         11 * i11i1Iii1I1[0] + 22 * i11i1Iii1I1[1] + 33 * i11i1Iii1I1[2] + 44 * i11i1Iii1I1[3] + 55 * i11i1Iii1I1[4] + 66 * i11i1Iii1I1[5] - 77 * i11i1Iii1I1[6] == 7975,
         21 * i11i1Iii1I1[0] + 23 * i11i1Iii1I1[1] + 3 * i11i1Iii1I1[2] + 24 * i11i1Iii1I1[3] - 55 * i11i1Iii1I1[4] + 6 * i11i1Iii1I1[5] - 7 * i11i1Iii1I1[6] + 15 * i11i1Iii1I1[7] == 229,
         2 * i11i1Iii1I1[0] + 26 * i11i1Iii1I1[1] + 13 * i11i1Iii1I1[2] + 0 * i11i1Iii1I1[3] - 65 * i11i1Iii1I1[4] + 15 * i11i1Iii1I1[5] + 29 * i11i1Iii1I1[6] + 1 * i11i1Iii1I1[7] + 20 * i11i1Iii1I1[8] == 2107,
         10 * i11i1Iii1I1[0] + 7 * i11i1Iii1I1[1] + -9 * i11i1Iii1I1[2] + 6 * i11i1Iii1I1[3] + 7 * i11i1Iii1I1[4] + 1 * i11i1Iii1I1[5] + 22 * i11i1Iii1I1[6] + 21 * i11i1Iii1I1[7] - 22 * i11i1Iii1I1[8] + 30 * i11i1Iii1I1[9] == 4037,
         15 * i11i1Iii1I1[0] + 59 * i11i1Iii1I1[1] + 56 * i11i1Iii1I1[2] + 66 * i11i1Iii1I1[3] + 7 * i11i1Iii1I1[4] + 1 * i11i1Iii1I1[5] - 122 * i11i1Iii1I1[6] + 21 * i11i1Iii1I1[7] + 32 * i11i1Iii1I1[8] + 3 * i11i1Iii1I1[9] - 10 * i11i1Iii1I1[10] == 4950,
         13 * i11i1Iii1I1[0] + 66 * i11i1Iii1I1[1] + 29 * i11i1Iii1I1[2] + 39 * i11i1Iii1I1[3] - 33 * i11i1Iii1I1[4] + 13 * i11i1Iii1I1[5] - 2 * i11i1Iii1I1[6] + 42 * i11i1Iii1I1[7] + 62 * i11i1Iii1I1[8] + 1 * i11i1Iii1I1[9] - 10 * i11i1Iii1I1[10] + 11 * i11i1Iii1I1[11] == 12544,
         23 * i11i1Iii1I1[0] + 6 * i11i1Iii1I1[1] + 29 * i11i1Iii1I1[2] + 3 * i11i1Iii1I1[3] - 3 * i11i1Iii1I1[4] + 63 * i11i1Iii1I1[5] - 25 * i11i1Iii1I1[6] + 2 * i11i1Iii1I1[7] + 32 * i11i1Iii1I1[8] + 1 * i11i1Iii1I1[9] - 10 * i11i1Iii1I1[10] + 11 * i11i1Iii1I1[11] - 12 * i11i1Iii1I1[12] == 6585,
         223 * i11i1Iii1I1[0] + 6 * i11i1Iii1I1[1] - 29 * i11i1Iii1I1[2] - 53 * i11i1Iii1I1[3] - 3 * i11i1Iii1I1[4] + 3 * i11i1Iii1I1[5] - 65 * i11i1Iii1I1[6] + 0 * i11i1Iii1I1[7] + 36 * i11i1Iii1I1[8] + 1 * i11i1Iii1I1[9] - 15 * i11i1Iii1I1[10] + 16 * i11i1Iii1I1[11] - 18 * i11i1Iii1I1[12] + 13 * i11i1Iii1I1[13] == 6893,
         29 * i11i1Iii1I1[0] + 13 * i11i1Iii1I1[1] - 9 * i11i1Iii1I1[2] - 93 * i11i1Iii1I1[3] + 33 * i11i1Iii1I1[4] + 6 * i11i1Iii1I1[5] + 65 * i11i1Iii1I1[6] + 1 * i11i1Iii1I1[7] - 36 * i11i1Iii1I1[8] + 0 * i11i1Iii1I1[9] - 16 * i11i1Iii1I1[10] + 96 * i11i1Iii1I1[11] - 68 * i11i1Iii1I1[12] + 33 * i11i1Iii1I1[13] - 14 * i11i1Iii1I1[14] == 1883,
         69 * i11i1Iii1I1[0] + 77 * i11i1Iii1I1[1] - 93 * i11i1Iii1I1[2] - 12 * i11i1Iii1I1[3] + 0 * i11i1Iii1I1[4] + 0 * i11i1Iii1I1[5] + 1 * i11i1Iii1I1[6] + 16 * i11i1Iii1I1[7] + 36 * i11i1Iii1I1[8] + 6 * i11i1Iii1I1[9] + 19 * i11i1Iii1I1[10] + 66 * i11i1Iii1I1[11] - 8 * i11i1Iii1I1[12] + 38 * i11i1Iii1I1[13] - 16 * i11i1Iii1I1[14] + 15 * i11i1Iii1I1[15] == 8257,
         23 * i11i1Iii1I1[0] + 2 * i11i1Iii1I1[1] - 3 * i11i1Iii1I1[2] - 11 * i11i1Iii1I1[3] + 12 * i11i1Iii1I1[4] + 24 * i11i1Iii1I1[5] + 1 * i11i1Iii1I1[6] + 6 * i11i1Iii1I1[7] + 14 * i11i1Iii1I1[8] - 0 * i11i1Iii1I1[9] + 1 * i11i1Iii1I1[10] + 68 * i11i1Iii1I1[11] - 18 * i11i1Iii1I1[12] + 68 * i11i1Iii1I1[13] - 26 * i11i1Iii1I1[14] + 15 * i11i1Iii1I1[15] - 16 * i11i1Iii1I1[16] == 5847,
         24 * i11i1Iii1I1[0] + 0 * i11i1Iii1I1[1] - 1 * i11i1Iii1I1[2] - 15 * i11i1Iii1I1[3] + 13 * i11i1Iii1I1[4] + 4 * i11i1Iii1I1[5] + 16 * i11i1Iii1I1[6] + 67 * i11i1Iii1I1[7] + 146 * i11i1Iii1I1[8] - 50 * i11i1Iii1I1[9] + 16 * i11i1Iii1I1[10] + 6 * i11i1Iii1I1[11] - 1 * i11i1Iii1I1[12] + 69 * i11i1Iii1I1[13] - 27 * i11i1Iii1I1[14] + 45 * i11i1Iii1I1[15] - 6 * i11i1Iii1I1[16] + 17 * i11i1Iii1I1[17] == 18257,
         25 * i11i1Iii1I1[0] + 26 * i11i1Iii1I1[1] - 89 * i11i1Iii1I1[2] + 16 * i11i1Iii1I1[3] + 19 * i11i1Iii1I1[4] + 44 * i11i1Iii1I1[5] + 36 * i11i1Iii1I1[6] + 66 * i11i1Iii1I1[7] - 150 * i11i1Iii1I1[8] - 250 * i11i1Iii1I1[9] + 166 * i11i1Iii1I1[10] + 126 * i11i1Iii1I1[11] - 11 * i11i1Iii1I1[12] + 690 * i11i1Iii1I1[13] - 207 * i11i1Iii1I1[14] + 46 * i11i1Iii1I1[15] + 6 * i11i1Iii1I1[16] + 7 * i11i1Iii1I1[17] - 18 * i11i1Iii1I1[18] == 12591,
         5 * i11i1Iii1I1[0] + 26 * i11i1Iii1I1[1] + 8 * i11i1Iii1I1[2] + 160 * i11i1Iii1I1[3] + 9 * i11i1Iii1I1[4] - 4 * i11i1Iii1I1[5] + 36 * i11i1Iii1I1[6] + 6 * i11i1Iii1I1[7] - 15 * i11i1Iii1I1[8] - 20 * i11i1Iii1I1[9] + 66 * i11i1Iii1I1[10] + 16 * i11i1Iii1I1[11] - 1 * i11i1Iii1I1[12] + 690 * i11i1Iii1I1[13] - 20 * i11i1Iii1I1[14] + 46 * i11i1Iii1I1[15] + 6 * i11i1Iii1I1[16] + 7 * i11i1Iii1I1[17] - 18 * i11i1Iii1I1[18] + 19 * i11i1Iii1I1[19] == 52041,
         29 * i11i1Iii1I1[0] - 26 * i11i1Iii1I1[1] + 0 * i11i1Iii1I1[2] + 60 * i11i1Iii1I1[3] + 90 * i11i1Iii1I1[4] - 4 * i11i1Iii1I1[5] + 6 * i11i1Iii1I1[6] + 6 * i11i1Iii1I1[7] - 16 * i11i1Iii1I1[8] - 21 * i11i1Iii1I1[9] + 69 * i11i1Iii1I1[10] + 6 * i11i1Iii1I1[11] - 12 * i11i1Iii1I1[12] + 69 * i11i1Iii1I1[13] - 20 * i11i1Iii1I1[14] - 46 * i11i1Iii1I1[15] + 65 * i11i1Iii1I1[16] + 0 * i11i1Iii1I1[17] - 1 * i11i1Iii1I1[18] + 39 * i11i1Iii1I1[19] - 20 * i11i1Iii1I1[20] == 20253,
         45 * i11i1Iii1I1[0] - 56 * i11i1Iii1I1[1] + 10 * i11i1Iii1I1[2] + 650 * i11i1Iii1I1[3] - 900 * i11i1Iii1I1[4] + 44 * i11i1Iii1I1[5] + 66 * i11i1Iii1I1[6] - 6 * i11i1Iii1I1[7] - 6 * i11i1Iii1I1[8] - 21 * i11i1Iii1I1[9] + 9 * i11i1Iii1I1[10] - 6 * i11i1Iii1I1[11] - 12 * i11i1Iii1I1[12] + 69 * i11i1Iii1I1[13] - 2 * i11i1Iii1I1[14] - 406 * i11i1Iii1I1[15] + 651 * i11i1Iii1I1[16] + 2 * i11i1Iii1I1[17] - 10 * i11i1Iii1I1[18] + 69 * i11i1Iii1I1[19] - 0 * i11i1Iii1I1[20] + 21 * i11i1Iii1I1[21] == 18768,
         555 * i11i1Iii1I1[0] - 6666 * i11i1Iii1I1[1] + 70 * i11i1Iii1I1[2] + 510 * i11i1Iii1I1[3] - 90 * i11i1Iii1I1[4] + 499 * i11i1Iii1I1[5] + 66 * i11i1Iii1I1[6] - 66 * i11i1Iii1I1[7] - 610 * i11i1Iii1I1[8] - 221 * i11i1Iii1I1[9] + 9 * i11i1Iii1I1[10] - 23 * i11i1Iii1I1[11] - 102 * i11i1Iii1I1[12] + 6 * i11i1Iii1I1[13] + 2050 * i11i1Iii1I1[14] - 406 * i11i1Iii1I1[15] + 665 * i11i1Iii1I1[16] + 333 * i11i1Iii1I1[17] + 100 * i11i1Iii1I1[18] + 609 * i11i1Iii1I1[19] + 777 * i11i1Iii1I1[20] + 201 * i11i1Iii1I1[21] - 22 * i11i1Iii1I1[22] == 111844,
         1 * i11i1Iii1I1[0] - 22 * i11i1Iii1I1[1] + 333 * i11i1Iii1I1[2] + 4444 * i11i1Iii1I1[3] - 5555 * i11i1Iii1I1[4] + 6666 * i11i1Iii1I1[5] - 666 * i11i1Iii1I1[6] + 676 * i11i1Iii1I1[7] - 660 * i11i1Iii1I1[8] - 22 * i11i1Iii1I1[9] + 9 * i11i1Iii1I1[10] - 73 * i11i1Iii1I1[11] - 107 * i11i1Iii1I1[12] + 6 * i11i1Iii1I1[13] + 250 * i11i1Iii1I1[14] - 6 * i11i1Iii1I1[15] + 65 * i11i1Iii1I1[16] + 39 * i11i1Iii1I1[17] + 10 * i11i1Iii1I1[18] + 69 * i11i1Iii1I1[19] + 777 * i11i1Iii1I1[20] + 201 * i11i1Iii1I1[21] - 2 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] == 159029,
         520 * i11i1Iii1I1[0] - 222 * i11i1Iii1I1[1] + 333 * i11i1Iii1I1[2] + 4 * i11i1Iii1I1[3] - 56655 * i11i1Iii1I1[4] + 6666 * i11i1Iii1I1[5] + 666 * i11i1Iii1I1[6] + 66 * i11i1Iii1I1[7] - 60 * i11i1Iii1I1[8] - 220 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 73 * i11i1Iii1I1[11] + 1007 * i11i1Iii1I1[12] + 7777 * i11i1Iii1I1[13] + 2500 * i11i1Iii1I1[14] + 6666 * i11i1Iii1I1[15] + 605 * i11i1Iii1I1[16] + 390 * i11i1Iii1I1[17] + 100 * i11i1Iii1I1[18] + 609 * i11i1Iii1I1[19] + 99999 * i11i1Iii1I1[20] + 210 * i11i1Iii1I1[21] + 232 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 24 * i11i1Iii1I1[24] == 2762025,
         1323 * i11i1Iii1I1[0] - 22 * i11i1Iii1I1[1] + 333 * i11i1Iii1I1[2] + 4 * i11i1Iii1I1[3] - 55 * i11i1Iii1I1[4] + 666 * i11i1Iii1I1[5] + 666 * i11i1Iii1I1[6] + 66 * i11i1Iii1I1[7] - 660 * i11i1Iii1I1[8] - 220 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 3 * i11i1Iii1I1[11] + 100 * i11i1Iii1I1[12] + 777 * i11i1Iii1I1[13] + 2500 * i11i1Iii1I1[14] + 6666 * i11i1Iii1I1[15] + 605 * i11i1Iii1I1[16] + 390 * i11i1Iii1I1[17] + 100 * i11i1Iii1I1[18] + 609 * i11i1Iii1I1[19] + 9999 * i11i1Iii1I1[20] + 210 * i11i1Iii1I1[21] + 232 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 24 * i11i1Iii1I1[24] + 25 * i11i1Iii1I1[25] == 1551621,
         777 * i11i1Iii1I1[0] - 22 * i11i1Iii1I1[1] + 6969 * i11i1Iii1I1[2] + 4 * i11i1Iii1I1[3] - 55 * i11i1Iii1I1[4] + 666 * i11i1Iii1I1[5] - 6 * i11i1Iii1I1[6] + 96 * i11i1Iii1I1[7] - 60 * i11i1Iii1I1[8] - 220 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 3 * i11i1Iii1I1[11] + 100 * i11i1Iii1I1[12] + 777 * i11i1Iii1I1[13] + 250 * i11i1Iii1I1[14] + 666 * i11i1Iii1I1[15] + 65 * i11i1Iii1I1[16] + 90 * i11i1Iii1I1[17] + 100 * i11i1Iii1I1[18] + 609 * i11i1Iii1I1[19] + 999 * i11i1Iii1I1[20] + 21 * i11i1Iii1I1[21] + 232 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 24 * i11i1Iii1I1[24] + 25 * i11i1Iii1I1[25] - 26 * i11i1Iii1I1[26] == 948348,
         97 * i11i1Iii1I1[0] - 22 * i11i1Iii1I1[1] + 6969 * i11i1Iii1I1[2] + 4 * i11i1Iii1I1[3] - 56 * i11i1Iii1I1[4] + 96 * i11i1Iii1I1[5] - 6 * i11i1Iii1I1[6] + 96 * i11i1Iii1I1[7] - 60 * i11i1Iii1I1[8] - 20 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 3 * i11i1Iii1I1[11] + 10 * i11i1Iii1I1[12] + 707 * i11i1Iii1I1[13] + 250 * i11i1Iii1I1[14] + 666 * i11i1Iii1I1[15] + -9 * i11i1Iii1I1[16] + 90 * i11i1Iii1I1[17] + -2 * i11i1Iii1I1[18] + 609 * i11i1Iii1I1[19] + 0 * i11i1Iii1I1[20] + 21 * i11i1Iii1I1[21] + 2 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 24 * i11i1Iii1I1[24] + 25 * i11i1Iii1I1[25] - 26 * i11i1Iii1I1[26] + 27 * i11i1Iii1I1[27] == 777044,
         177 * i11i1Iii1I1[0] - 22 * i11i1Iii1I1[1] + 699 * i11i1Iii1I1[2] + 64 * i11i1Iii1I1[3] - 56 * i11i1Iii1I1[4] - 96 * i11i1Iii1I1[5] - 66 * i11i1Iii1I1[6] + 96 * i11i1Iii1I1[7] - 60 * i11i1Iii1I1[8] - 20 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 3 * i11i1Iii1I1[11] + 10 * i11i1Iii1I1[12] + 707 * i11i1Iii1I1[13] + 250 * i11i1Iii1I1[14] + 666 * i11i1Iii1I1[15] + -9 * i11i1Iii1I1[16] + 0 * i11i1Iii1I1[17] + -2 * i11i1Iii1I1[18] + 69 * i11i1Iii1I1[19] + 0 * i11i1Iii1I1[20] + 21 * i11i1Iii1I1[21] + 222 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 224 * i11i1Iii1I1[24] + 25 * i11i1Iii1I1[25] - 26 * i11i1Iii1I1[26] + 27 * i11i1Iii1I1[27] - 28 * i11i1Iii1I1[28] == 185016,
         77 * i11i1Iii1I1[0] - 2 * i11i1Iii1I1[1] + 6 * i11i1Iii1I1[2] + 6 * i11i1Iii1I1[3] - 96 * i11i1Iii1I1[4] - 9 * i11i1Iii1I1[5] - 6 * i11i1Iii1I1[6] + 96 * i11i1Iii1I1[7] - 0 * i11i1Iii1I1[8] - 20 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 3 * i11i1Iii1I1[11] + 10 * i11i1Iii1I1[12] + 707 * i11i1Iii1I1[13] + 250 * i11i1Iii1I1[14] + 666 * i11i1Iii1I1[15] + -9 * i11i1Iii1I1[16] + 0 * i11i1Iii1I1[17] + -2 * i11i1Iii1I1[18] + 9 * i11i1Iii1I1[19] + 0 * i11i1Iii1I1[20] + 21 * i11i1Iii1I1[21] + 222 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 224 * i11i1Iii1I1[24] + 26 * i11i1Iii1I1[25] - -58 * i11i1Iii1I1[26] + 27 * i11i1Iii1I1[27] - 2 * i11i1Iii1I1[28] + 29 * i11i1Iii1I1[29] == 130106]
        if all(ii1iIi1i11i):
            print("Congratulation!!!")
        else:
            print("wrong_wrong!!!")
```

经过混淆的python代码，不过也就换了一些变量名啥的，自行替换一下就可以了

程序的整体逻辑就是先将输入的flag字符串中的每个字符的出现次数进行统计，然后将每个字符替换成其出现次数的那个数字，这是第一次check。接下来还是统计字符的出现次数，转换成特定排序的字符串，就是按顺序，每个字符后面跟的数字就是这个字符出现的次数，比如输入HZNUCTF{111}，那么就会输出H1Z1N1U1C1T1F1{113}1，最后进行方程式的约束检测

以下是解题脚本

```python
from z3 import *

# 定义变量 enc[0] 到 enc[29]
enc = [Int(f"enc_{i}") for i in range(30)]

# 创建求解器
solver = Solver()

# 定义方程组
equations = [
    7 * enc[0] == 504,
    9 * enc[0] - 5 * enc[1] == 403,
    2 * enc[0] - 5 * enc[1] + 10 * enc[2] == 799,
    3 * enc[0] + 8 * enc[1] + 15 * enc[2] + 20 * enc[3] == 2938,
    5 * enc[0] + 15 * enc[1] + 20 * enc[2] - 19 * enc[3] + 1 * enc[4] == 2042,
    7 * enc[0] + 1 * enc[1] + 9 * enc[2] - 11 * enc[3] + 2 * enc[4] + 5 * enc[5] == 1225,
    11 * enc[0] + 22 * enc[1] + 33 * enc[2] + 44 * enc[3] + 55 * enc[4] + 66 * enc[5] - 77 * enc[6] == 7975,
    21 * enc[0] + 23 * enc[1] + 3 * enc[2] + 24 * enc[3] - 55 * enc[4] + 6 * enc[5] - 7 * enc[6] + 15 * enc[7] == 229,
    2 * enc[0] + 26 * enc[1] + 13 * enc[2] + 0 * enc[3] - 65 * enc[4] + 15 * enc[5] + 29 * enc[6] + 1 * enc[7] + 20 *
    enc[8] == 2107,
    10 * enc[0] + 7 * enc[1] + -9 * enc[2] + 6 * enc[3] + 7 * enc[4] + 1 * enc[5] + 22 * enc[6] + 21 * enc[7] - 22 *
    enc[8] + 30 * enc[9] == 4037,
    15 * enc[0] + 59 * enc[1] + 56 * enc[2] + 66 * enc[3] + 7 * enc[4] + 1 * enc[5] - 122 * enc[6] + 21 * enc[7] + 32 *
    enc[8] + 3 * enc[9] - 10 * enc[10] == 4950,
    13 * enc[0] + 66 * enc[1] + 29 * enc[2] + 39 * enc[3] - 33 * enc[4] + 13 * enc[5] - 2 * enc[6] + 42 * enc[7] + 62 *
    enc[8] + 1 * enc[9] - 10 * enc[10] + 11 * enc[11] == 12544,
    23 * enc[0] + 6 * enc[1] + 29 * enc[2] + 3 * enc[3] - 3 * enc[4] + 63 * enc[5] - 25 * enc[6] + 2 * enc[7] + 32 *
    enc[8] + 1 * enc[9] - 10 * enc[10] + 11 * enc[11] - 12 * enc[12] == 6585,
    223 * enc[0] + 6 * enc[1] - 29 * enc[2] - 53 * enc[3] - 3 * enc[4] + 3 * enc[5] - 65 * enc[6] + 0 * enc[7] + 36 *
    enc[8] + 1 * enc[9] - 15 * enc[10] + 16 * enc[11] - 18 * enc[12] + 13 * enc[13] == 6893,
    29 * enc[0] + 13 * enc[1] - 9 * enc[2] - 93 * enc[3] + 33 * enc[4] + 6 * enc[5] + 65 * enc[6] + 1 * enc[7] - 36 *
    enc[8] + 0 * enc[9] - 16 * enc[10] + 96 * enc[11] - 68 * enc[12] + 33 * enc[13] - 14 * enc[14] == 1883,
    69 * enc[0] + 77 * enc[1] - 93 * enc[2] - 12 * enc[3] + 0 * enc[4] + 0 * enc[5] + 1 * enc[6] + 16 * enc[7] + 36 *
    enc[8] + 6 * enc[9] + 19 * enc[10] + 66 * enc[11] - 8 * enc[12] + 38 * enc[13] - 16 * enc[14] + 15 * enc[
        15] == 8257,
    23 * enc[0] + 2 * enc[1] - 3 * enc[2] - 11 * enc[3] + 12 * enc[4] + 24 * enc[5] + 1 * enc[6] + 6 * enc[7] + 14 *
    enc[8] - 0 * enc[9] + 1 * enc[10] + 68 * enc[11] - 18 * enc[12] + 68 * enc[13] - 26 * enc[14] + 15 * enc[15] - 16 *
    enc[16] == 5847,
    24 * enc[0] + 0 * enc[1] - 1 * enc[2] - 15 * enc[3] + 13 * enc[4] + 4 * enc[5] + 16 * enc[6] + 67 * enc[7] + 146 *
    enc[8] - 50 * enc[9] + 16 * enc[10] + 6 * enc[11] - 1 * enc[12] + 69 * enc[13] - 27 * enc[14] + 45 * enc[15] - 6 *
    enc[16] + 17 * enc[17] == 18257,
    25 * enc[0] + 26 * enc[1] - 89 * enc[2] + 16 * enc[3] + 19 * enc[4] + 44 * enc[5] + 36 * enc[6] + 66 * enc[
        7] - 150 * enc[8] - 250 * enc[9] + 166 * enc[10] + 126 * enc[11] - 11 * enc[12] + 690 * enc[13] - 207 * enc[
        14] + 46 * enc[15] + 6 * enc[16] + 7 * enc[17] - 18 * enc[18] == 12591,
    5 * enc[0] + 26 * enc[1] + 8 * enc[2] + 160 * enc[3] + 9 * enc[4] - 4 * enc[5] + 36 * enc[6] + 6 * enc[7] - 15 *
    enc[8] - 20 * enc[9] + 66 * enc[10] + 16 * enc[11] - 1 * enc[12] + 690 * enc[13] - 20 * enc[14] + 46 * enc[15] + 6 *
    enc[16] + 7 * enc[17] - 18 * enc[18] + 19 * enc[19] == 52041,
    29 * enc[0] - 26 * enc[1] + 0 * enc[2] + 60 * enc[3] + 90 * enc[4] - 4 * enc[5] + 6 * enc[6] + 6 * enc[7] - 16 *
    enc[8] - 21 * enc[9] + 69 * enc[10] + 6 * enc[11] - 12 * enc[12] + 69 * enc[13] - 20 * enc[14] - 46 * enc[15] + 65 *
    enc[16] + 0 * enc[17] - 1 * enc[18] + 39 * enc[19] - 20 * enc[20] == 20253,
    45 * enc[0] - 56 * enc[1] + 10 * enc[2] + 650 * enc[3] - 900 * enc[4] + 44 * enc[5] + 66 * enc[6] - 6 * enc[7] - 6 *
    enc[8] - 21 * enc[9] + 9 * enc[10] - 6 * enc[11] - 12 * enc[12] + 69 * enc[13] - 2 * enc[14] - 406 * enc[15] + 651 *
    enc[16] + 2 * enc[17] - 10 * enc[18] + 69 * enc[19] - 0 * enc[20] + 21 * enc[21] == 18768,
    555 * enc[0] - 6666 * enc[1] + 70 * enc[2] + 510 * enc[3] - 90 * enc[4] + 499 * enc[5] + 66 * enc[6] - 66 * enc[
        7] - 610 * enc[8] - 221 * enc[9] + 9 * enc[10] - 23 * enc[11] - 102 * enc[12] + 6 * enc[13] + 2050 * enc[
        14] - 406 * enc[15] + 665 * enc[16] + 333 * enc[17] + 100 * enc[18] + 609 * enc[19] + 777 * enc[20] + 201 * enc[
        21] - 22 * enc[22] == 111844,
    1 * enc[0] - 22 * enc[1] + 333 * enc[2] + 4444 * enc[3] - 5555 * enc[4] + 6666 * enc[5] - 666 * enc[6] + 676 * enc[
        7] - 660 * enc[8] - 22 * enc[9] + 9 * enc[10] - 73 * enc[11] - 107 * enc[12] + 6 * enc[13] + 250 * enc[14] - 6 *
    enc[15] + 65 * enc[16] + 39 * enc[17] + 10 * enc[18] + 69 * enc[19] + 777 * enc[20] + 201 * enc[21] - 2 * enc[
        22] + 23 * enc[23] == 159029,
    520 * enc[0] - 222 * enc[1] + 333 * enc[2] + 4 * enc[3] - 56655 * enc[4] + 6666 * enc[5] + 666 * enc[6] + 66 * enc[
        7] - 60 * enc[8] - 220 * enc[9] + 99 * enc[10] + 73 * enc[11] + 1007 * enc[12] + 7777 * enc[13] + 2500 * enc[
        14] + 6666 * enc[15] + 605 * enc[16] + 390 * enc[17] + 100 * enc[18] + 609 * enc[19] + 99999 * enc[20] + 210 *
    enc[21] + 232 * enc[22] + 23 * enc[23] - 24 * enc[24] == 2762025,
    1323 * enc[0] - 22 * enc[1] + 333 * enc[2] + 4 * enc[3] - 55 * enc[4] + 666 * enc[5] + 666 * enc[6] + 66 * enc[
        7] - 660 * enc[8] - 220 * enc[9] + 99 * enc[10] + 3 * enc[11] + 100 * enc[12] + 777 * enc[13] + 2500 * enc[
        14] + 6666 * enc[15] + 605 * enc[16] + 390 * enc[17] + 100 * enc[18] + 609 * enc[19] + 9999 * enc[20] + 210 *
    enc[21] + 232 * enc[22] + 23 * enc[23] - 24 * enc[24] + 25 * enc[25] == 1551621,
    777 * enc[0] - 22 * enc[1] + 6969 * enc[2] + 4 * enc[3] - 55 * enc[4] + 666 * enc[5] - 6 * enc[6] + 96 * enc[
        7] - 60 * enc[8] - 220 * enc[9] + 99 * enc[10] + 3 * enc[11] + 100 * enc[12] + 777 * enc[13] + 250 * enc[
        14] + 666 * enc[15] + 65 * enc[16] + 90 * enc[17] + 100 * enc[18] + 609 * enc[19] + 999 * enc[20] + 21 * enc[
        21] + 232 * enc[22] + 23 * enc[23] - 24 * enc[24] + 25 * enc[25] - 26 * enc[26] == 948348,
    97 * enc[0] - 22 * enc[1] + 6969 * enc[2] + 4 * enc[3] - 56 * enc[4] + 96 * enc[5] - 6 * enc[6] + 96 * enc[7] - 60 *
    enc[8] - 20 * enc[9] + 99 * enc[10] + 3 * enc[11] + 10 * enc[12] + 707 * enc[13] + 250 * enc[14] + 666 * enc[
        15] + -9 * enc[16] + 90 * enc[17] + -2 * enc[18] + 609 * enc[19] + 0 * enc[20] + 21 * enc[21] + 2 * enc[
        22] + 23 * enc[23] - 24 * enc[24] + 25 * enc[25] - 26 * enc[26] + 27 * enc[27] == 777044,
    177 * enc[0] - 22 * enc[1] + 699 * enc[2] + 64 * enc[3] - 56 * enc[4] - 96 * enc[5] - 66 * enc[6] + 96 * enc[
        7] - 60 * enc[8] - 20 * enc[9] + 99 * enc[10] + 3 * enc[11] + 10 * enc[12] + 707 * enc[13] + 250 * enc[
        14] + 666 * enc[15] + -9 * enc[16] + 0 * enc[17] + -2 * enc[18] + 69 * enc[19] + 0 * enc[20] + 21 * enc[
        21] + 222 * enc[22] + 23 * enc[23] - 224 * enc[24] + 25 * enc[25] - 26 * enc[26] + 27 * enc[27] - 28 * enc[
        28] == 185016,
    77 * enc[0] - 2 * enc[1] + 6 * enc[2] + 6 * enc[3] - 96 * enc[4] - 9 * enc[5] - 6 * enc[6] + 96 * enc[7] - 0 * enc[
        8] - 20 * enc[9] + 99 * enc[10] + 3 * enc[11] + 10 * enc[12] + 707 * enc[13] + 250 * enc[14] + 666 * enc[
        15] + -9 * enc[16] + 0 * enc[17] + -2 * enc[18] + 9 * enc[19] + 0 * enc[20] + 21 * enc[21] + 222 * enc[
        22] + 23 * enc[23] - 224 * enc[24] + 26 * enc[25] - -58 * enc[26] + 27 * enc[27] - 2 * enc[28] + 29 * enc[
        29] == 130106
]

# 将所有方程添加到求解器中
for eq in equations:
    solver.add(eq)

# 求解
if solver.check() == sat:
    model = solver.model()
    # 输出解
    result = [chr(model[enc[i]].as_long()) for i in range(30)]
    for i in range(30):
        print(result[i], end="")
else:
    print("没有解")
```

H1Z1N1U1C1T1F1{1a6d275f7-463}1拿到flag中所含的字符，那么就可以根据111111116257645365477364777645752361进行还原

**HZNUCTF{ad7fa-76a7-ff6a-fffa-7f7d6a}**

--------------------------------------------------------------------------------------------------------------------------------------------------------

### randomsystem

考点总结：自定义加密，伪随机，TLS回调，花指令

题目描述：名字乱取的...flag格式为HZNUCTF{}

WP：

题目附件无壳，直接ida64打开分析

```c
__int64 sub_412370()
{
  int v0; // edx
  int v1; // eax
  __int64 v3; // [esp-8h] [ebp-78Ch]
  char v4; // [esp+0h] [ebp-784h]
  char v5; // [esp+0h] [ebp-784h]
  char v6; // [esp+0h] [ebp-784h]
  char v7; // [esp+0h] [ebp-784h]
  char v8; // [esp+0h] [ebp-784h]
  int m; // [esp+250h] [ebp-534h]
  int k; // [esp+25Ch] [ebp-528h]
  unsigned int v11; // [esp+268h] [ebp-51Ch]
  int j; // [esp+274h] [ebp-510h]
  char v13; // [esp+283h] [ebp-501h]
  int i; // [esp+298h] [ebp-4ECh]
  int rand_num[34]; // [esp+2A4h] [ebp-4E0h] BYREF
  char Str[20]; // [esp+32Ch] [ebp-458h] BYREF
  int enc[66]; // [esp+340h] [ebp-444h] BYREF
  _OWORD v18[16]; // [esp+448h] [ebp-33Ch] BYREF
  char v19[264]; // [esp+550h] [ebp-234h] BYREF
  char Destination[96]; // [esp+658h] [ebp-12Ch] BYREF
  char v21; // [esp+6B8h] [ebp-CCh] BYREF
  char Source[76]; // [esp+6C0h] [ebp-C4h] BYREF
  int v23; // [esp+70Ch] [ebp-78h] BYREF
  int v24; // [esp+710h] [ebp-74h]
  int v25; // [esp+714h] [ebp-70h]
  int v26; // [esp+718h] [ebp-6Ch]
  char v27; // [esp+71Ch] [ebp-68h]
  int v28[4]; // [esp+728h] [ebp-5Ch] BYREF
  char v29[72]; // [esp+738h] [ebp-4Ch] BYREF
  int savedregs; // [esp+784h] [ebp+0h] BYREF

  sub_41137A(&unk_41E0A9);
  v23 = 0;
  v24 = 0;
  v25 = 0;
  v26 = 0;
  v27 = 0;
  j_memset(v19, 0, 0x100u);
  j_memset(v18, 0, sizeof(v18));
  strcpy(Str, "KeYkEy!!");
  enc[0] = 376;
  enc[1] = 356;
  enc[2] = 169;
  enc[3] = 501;
  enc[4] = 277;
  enc[5] = 329;
  enc[6] = 139;
  enc[7] = 342;
  enc[8] = 380;
  enc[9] = 365;
  enc[10] = 162;
  enc[11] = 258;
  enc[12] = 381;
  enc[13] = 339;
  enc[14] = 347;
  enc[15] = 307;
  enc[16] = 263;
  enc[17] = 359;
  enc[18] = 162;
  enc[19] = 484;
  enc[20] = 310;
  enc[21] = 333;
  enc[22] = 346;
  enc[23] = 339;
  enc[24] = 150;
  enc[25] = 194;
  enc[26] = 175;
  enc[27] = 344;
  enc[28] = 158;
  enc[29] = 250;
  enc[30] = 128;
  enc[31] = 175;
  enc[32] = 158;
  enc[33] = 173;
  enc[34] = 152;
  enc[35] = 379;
  enc[36] = 158;
  enc[37] = 292;
  enc[38] = 130;
  enc[39] = 365;
  enc[40] = 197;
  enc[41] = 20;
  enc[42] = 197;
  enc[43] = 161;
  enc[44] = 198;
  enc[45] = 10;
  enc[46] = 207;
  enc[47] = 244;
  enc[48] = 202;
  enc[49] = 14;
  enc[50] = 204;
  enc[51] = 176;
  enc[52] = 193;
  enc[53] = 255;
  enc[54] = 35;
  enc[55] = 7;
  enc[56] = 158;
  enc[57] = 181;
  enc[58] = 145;
  enc[59] = 353;
  enc[60] = 153;
  enc[61] = 357;
  enc[62] = 246;
  enc[63] = 151;
  printf("Welcome to HZNUCTF!!!\n", v4);
  printf("Enter something: \n", v5);
  scanf("%64s", (char)v29);
  sub_411339(v29, v28);                         // // 将以二进制形式输入的key先转成十六进制
  sub_41128F(v28[0], v28[1], &v23);
  if ( (char)v23 == 53                          // // 对key的检查
    && SBYTE1(v23) == 50
    && SBYTE2(v23) == 54
    && SHIBYTE(v23) == 53
    && (char)v24 == 53
    && SBYTE1(v24) == 54
    && SBYTE2(v24) == 54
    && SHIBYTE(v24) == 53
    && (char)v25 == 53
    && SBYTE1(v25) == 50
    && SBYTE2(v25) == 54
    && SHIBYTE(v25) == 53
    && (char)v26 == 53
    && SBYTE1(v26) == 51
    && SBYTE2(v26) == 54
    && SHIBYTE(v26) == 53 )
  {
    printf("good_job!!!\n", v6);
    printf("So, Plz input the flag:\n", v7);
    scanf("%73s", (char)&v21);
    strncpy_s(Destination, 0x41u, Source, 0x40u);
    sub_41127B();
    srand(Seed);                                // 伪随机初始化，但是这里的seed并不是看到的0，而是经过tls回调函数重新赋值的2025
    sub_41127B();
    j_memset(rand_num, 0, 0x80u);
    for ( i = 0; i < 32; ++i )                  // 伪随机数组
    {
      do
      {
        rand();
        v1 = sub_41127B() % 32;
        v13 = 1;
        for ( j = 0; j < i; ++j )
        {
          if ( rand_num[j] == v1 )
          {
            v13 = 0;
            break;
          }
        }
      }
      while ( !v13 );
      rand_num[i] = v1;
    }
    sub_41105F(Destination, rand_num);          // 对flag大括号里的内容进行处理，以生成的伪随机数作为下标进行打乱。但是有花指令
    sub_411307(v19, Destination);               // 将打乱后的flag大括号的内容处理为8*8的矩阵
    sub_411334(&v23, Str);                      // key的再赋值
    sub_4112DA(&dword_41C368, v19, v18);        // 矩阵乘法
    v11 = 0;
    for ( k = 0; k < 8; ++k )
    {
      for ( m = 0; m < 8; ++m )
      {
        *((_DWORD *)&v18[2 * k] + m) ^= Str[v11 % j_strlen(Str)];
        ++v11;
      }
    }
    if ( sub_411078(v18, enc) == 1 )
      printf("Congratulation!!!\n", v8);
  }
  else
  {
    printf("wrong_wrong!!!\n", v6);
  }
  sub_41120D(&savedregs, &dword_412D48, 0, v0);
  return v3;
}
```

main函数里的各个函数的逻辑都已注释好，但是有些函数在反编译时需要去花，考查的都是一些常见的花指令

![image-20250301181238957](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250301181238957.png)

![image-20250301181306358](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250301181306358.png)

sub_41105F函数

![image-20250301181412591](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250301181412591.png)

sub_411334函数

![image-20250301173037500](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250301173037500.png)

sub_4112DA函数

![image-20250301181720994](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250301181720994.png)

sub_411307函数

![image-20250301173312623](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250301173312623.png)

TLS回调函数

```c
__int64 __userpurge TlsCallback_0_0@<edx:eax>(int a1@<eax>, int a2@<edx>, int a3, int a4, int a5)
{
  __int64 v6; // [esp-8h] [ebp-200h]
  int j; // [esp+D0h] [ebp-128h]
  int i; // [esp+DCh] [ebp-11Ch]
  int v9; // [esp+E8h] [ebp-110h]
  int v10[65]; // [esp+F4h] [ebp-104h] BYREF
  int savedregs; // [esp+1F8h] [ebp+0h] BYREF

  Seed = 2025;
  v10[0] = 1;
  v10[1] = 1;
  v10[2] = 0;
  v10[3] = 1;
  v10[4] = 0;
  v10[5] = 0;
  v10[6] = 1;
  v10[7] = 0;
  v10[8] = 0;
  v10[9] = 1;
  v10[10] = 1;
  v10[11] = 0;
  v10[12] = 0;
  v10[13] = 1;
  v10[14] = 0;
  v10[15] = 1;
  v10[16] = 0;
  v10[17] = 0;
  v10[18] = 1;
  v10[19] = 1;
  v10[20] = 0;
  v10[21] = 1;
  v10[22] = 1;
  memset(&v10[23], 0, 16);
  v10[27] = 1;
  v10[28] = 0;
  v10[29] = 1;
  v10[30] = 0;
  v10[31] = 1;
  v10[32] = 0;
  v10[33] = 1;
  v10[34] = 0;
  v10[35] = 0;
  v10[36] = 1;
  v10[37] = 0;
  v10[38] = 1;
  memset(&v10[39], 0, 24);
  v10[45] = 1;
  v10[46] = 0;
  v10[47] = 1;
  memset(&v10[48], 0, 24);
  v10[54] = 1;
  v10[55] = 1;
  v10[56] = 0;
  v10[57] = 1;
  v10[58] = 1;
  memset(&v10[59], 0, 16);
  v10[63] = 1;
  v9 = 0;
  for ( i = 0; i < 8; ++i )
  {
    for ( j = 0; j < 8; ++j )
    {
      a2 = v10[v9];
      dword_41C368[8 * i + j] = a2;
      ++v9;
    }
    a1 = i + 1;
  }
  sub_41120D(&savedregs, &dword_411B50, a1, a2);
  return v6;
}
```

至于key的由来，注意观察

![image-20250301182215231](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250301182215231.png)

以及sub_411334函数的逻辑，可知key就是**ReVeReSe**，然后将其转为二进制，就是我们最开始输入程序的内容。

那么就可以写脚本解密了，先解异或，然后再来算矩阵

```c
#include <stdio.h>
#include <string.h>

int main() {
int enc[64];
    enc[0] = 376;
    enc[1] = 356;
    enc[2] = 169;
    enc[3] = 501;
    enc[4] = 277;
    enc[5] = 329;
    enc[6] = 139;
    enc[7] = 342;
    enc[8] = 380;
    enc[9] = 365;
    enc[10] = 162;
    enc[11] = 258;
    enc[12] = 381;
    enc[13] = 339;
    enc[14] = 347;
    enc[15] = 307;
    enc[16] = 263;
    enc[17] = 359;
    enc[18] = 162;
    enc[19] = 484;
    enc[20] = 310;
    enc[21] = 333;
    enc[22] = 346;
    enc[23] = 339;
    enc[24] = 150;
    enc[25] = 194;
    enc[26] = 175;
    enc[27] = 344;
    enc[28] = 158;
    enc[29] = 250;
    enc[30] = 128;
    enc[31] = 175;
    enc[32] = 158;
    enc[33] = 173;
    enc[34] = 152;
    enc[35] = 379;
    enc[36] = 158;
    enc[37] = 292;
    enc[38] = 130;
    enc[39] = 365;
    enc[40] = 197;
    enc[41] = 20;
    enc[42] = 197;
    enc[43] = 161;
    enc[44] = 198;
    enc[45] = 10;
    enc[46] = 207;
    enc[47] = 244;
    enc[48] = 202;
    enc[49] = 14;
    enc[50] = 204;
    enc[51] = 176;
    enc[52] = 193;
    enc[53] = 255;
    enc[54] = 35;
    enc[55] = 7;
    enc[56] = 158;
    enc[57] = 181;
    enc[58] = 145;
    enc[59] = 353;
    enc[60] = 153;
    enc[61] = 357;
    enc[62] = 246;
    enc[63] = 151;
    char key[9] = "ReVeReSe";
    
    for (int i = 0; i < 64; i++) {
        enc[i] ^= key[i % 8];
        printf("%d ", enc[i]);
    }
    return 0;
}
```

> 298 257 255 400 327 300 216 307 302 264 244 359 303 310 264 342 341 258 244 385 356 296 265 310 196 167 249 317 204 159 211 202 204 200 206 286 204 321 209 264 151 113 147 196 148 111 156 145 152 107 154 213 147 154 112 98 204 208 199 260 203 256 165 242

然后求与flag填充的矩阵相乘的矩阵的逆矩阵，可以使用在线网站

![image-20250301182503632](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250301182503632.png)

然后将结果和脚本解出的数据进行相乘

![image-20250301183206092](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250301183206092.png)

然后将结果提出来

```c
#include<stdio.h>

int main() {
   int enc[8][8] = {{102,100,49,49,118,53,54,100},{52,53,52,114,54,102,52,97},{99,98,45,49,101,97,56,100},{45,54,102,121,56,48,55,57},{53,97,102,56,51,122,102,114},{98,56,45,99,100,54,99,100},{99,50,52,116,99,97,55,53},{53,57,102,97,48,57,57,45}};
   for (int i = 0; i < 8; i++) {
		for (int j = 0; j < 8; j++) {
			printf("%c", enc[i][j]);
		}
   }
}
```

运行结果是fd11v56d454r6f4acb-1ea8d-6fy80795af83zfrb8-cd6cdc24tca7559fa099-

就差最后一步了，还原正确flag的次序

伪随机的种子是2025，根据伪代码的逻辑，生成32个不重复的伪随机数，并且都小于32，然后进行还原

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <windows.h>

int main() {
	int seed = 2025;
	srand(seed);
	int rand_num[32] = { 0 };
	for (int i = 0; i < 32; i++) {
		int enc;
		bool is_unique;
		do {
			enc = rand() % 32;
			is_unique = true;
			for (int j = 0; j < i; j++) {
				if (rand_num[j] == enc) {
					is_unique = false;
					break;
				}
			}
		} while (!is_unique); // 如果重复，重新生成随机数
		rand_num[i] = enc; // 将不重复的随机数放入数组
	}
   	char enc[] = "fd11v56d454r6f4acb-1ea8d-6fy80795af83zfrb8-cd6cdc24tca7559fa099-";
	size_t len = strlen(enc);
	for (int i = 0; i < len / 2; i++) {
			char temp = enc[i];
			enc[i] = enc[len - rand_num[i] - 1];
			enc[len - rand_num[i] - 1] = temp;
	}
	printf("%s", enc);
   	return 0;
}
```

拿到flag大括号的内容

3zfb899ac5c256d-7a8r59f0tccd-4fa6b8vfd111-a44ffy4r0-6dce5679da58

flag就是**HZNUCTF{3zfb899ac5c256d-7a8r59f0tccd-4fa6b8vfd111-a44ffy4r0-6dce5679da58}**





-------------------------------------------------------------------------------------------------------------------------------------

### index

考点总结：wasm，自定义加密，伪随机

题目描述：名字乱取的...flag格式为HZNUCTF{}

WP：

在出这题的时候出题人还不知道**ghidra**装插件之后可以很好的反编译wasm，那么现在有了的话就可以不那么痛苦的去手撕.o了。

并且这个题在开始的时候还是有些问题的，就是在伪随机数产生的时候，那个RAND_MAX，最开始没管这个数，结果导致我的源码和生成后的wasm中的数不一样，一个是0x7FFF，一个是0x7FFFFFFF，前者是源码中的，后者是附件中的，导致解密出问题。给受到影响的师傅磕一个了orz；同时感谢yuro orz。(下次测题得仔细点)当然，这个题最后还是有些问题，就是动态调试的时候还是有些问题，有些数据不知道被写到哪里去了...(以后不出这种不稳点的题了...)

插件的网址

> https://github.com/nneonneo/ghidra-wasm-plugin/

安装好之后，修一下wasm文件的文件头，附件中是大写的.ASM，标准的应该是.asm，改一下，就可以直接用ghidra分析了

反编译完成之后，**unnamed_function_12**就是主函数了，很清晰

```c
undefined4 unnamed_function_12(void)

{
  int iVar1;
  undefined8 *local_80 [4];
  undefined8 *local_70;
  int local_6c;
  int local_68;
  int local_64;
  byte local_60 [32];
  undefined8 local_40;
  undefined local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined local_10;
  undefined4 local_4;
  
  local_4 = 0;
  local_10 = 0;
  local_18 = 0;
  local_20 = 0;
  local_28 = 0;
  local_30 = 0;
  local_38 = 0;
  local_40 = 0;
  local_60[0x18] = 0;
  local_60[0x19] = 0;
  local_60[0x1a] = 0;
  local_60[0x1b] = 0;
  local_60[0x1c] = 0;
  local_60[0x1d] = 0;
  local_60[0x1e] = 0;
  local_60[0x1f] = 0;
  local_60[0x10] = 0;
  local_60[0x11] = 0;
  local_60[0x12] = 0;
  local_60[0x13] = 0;
  local_60[0x14] = 0;
  local_60[0x15] = 0;
  local_60[0x16] = 0;
  local_60[0x17] = 0;
  local_60[8] = 0;
  local_60[9] = 0;
  local_60[10] = 0;
  local_60[0xb] = 0;
  local_60[0xc] = 0;
  local_60[0xd] = 0;
  local_60[0xe] = 0;
  local_60[0xf] = 0;
  local_60[0] = 0;
  local_60[1] = 0;
  local_60[2] = 0;
  local_60[3] = 0;
  local_60[4] = 0;
  local_60[5] = 0;
  local_60[6] = 0;
  local_60[7] = 0;
  unnamed_function_14(s_Welcome_to_HZNUCTF!!!_ram_000100ae,0);
  unnamed_function_14(s_Plz_input_the_key:_ram_00010051,0);
  local_70 = &local_40;
  unnamed_function_17(0x10026,&local_70);
  iVar1 = unnamed_function_21(&local_40,0x11020);
  if (iVar1 == 0) {
    unnamed_function_7(&local_40);
    unnamed_function_14(s_Ok,_let's_go!!!_ram_0001007a,0);
    unnamed_function_14(s_Plz_input_the_flag:_ram_00010065,0);
    local_80[0] = &local_30;
    unnamed_function_17(0x10026,local_80);
    iVar1 = unnamed_function_22(&local_30);
    if (iVar1 == 0x20) {
      unnamed_function_9(&local_30,local_60);
      for (local_64 = 0; local_64 < 8; local_64 = local_64 + 1) {
        unnamed_function_11(local_60 + local_64 * 4,&local_40);
      }
      for (local_68 = 0; local_68 < 8; local_68 = local_68 + 1) {
        for (local_6c = 0; local_6c < 4; local_6c = local_6c + 1) {
          if ((uint)local_60[local_6c + local_68 * 4] !=
              *(uint *)(local_68 * 0x10 + 0x10fa0 + local_6c * 4)) {
            unnamed_function_14(s_wrong_wrong!!!_ram_00010042,0);
            return 0;
          }
        }
      }
      unnamed_function_14(s_Congratulation!!!_ram_0001008b,0);
    }
    else {
      unnamed_function_14(s_wrong_wrong!!!_ram_00010042,0);
    }
  }
  else {
    unnamed_function_14(s_wrong_wrong!!!_ram_0001009e,0);
  }
  return 0;
}
```

整体逻辑就是先输入key，然后判断key是否正确，接着对key进行异或处理，xor0x51， 完了输入flag，检查长度是否是32，接下来就是对flag字符顺序进行打乱，打乱完之后就进行异或处理。

接下来进行仔细分析

**unnamed_function_21**函数就是cmp，将输入的key进行比较，0x11020就是正确的key的存储地址，双击跳转过去即可拿到正确的key，

![image-20250413111916618](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250413111916618.png)

然后进入**unnamed_function_7**进行key的异或，xor 0x51

```c
void unnamed_function_7(int param1)

{
  int iVar1;
  undefined4 local_c;
  
  iVar1 = unnamed_function_22(param1);
  for (local_c = 0; local_c < iVar1; local_c = local_c + 1) {
    *(byte *)(param1 + local_c) = *(byte *)(param1 + local_c) ^ 0x51;
  }
  return;
}
```

接下来输入flag，然后判断长度，然后进入**unnamed_function_9**函数进行打乱

```c
void unnamed_function_9(int param1,int param2)

{
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_c = 0;
  unnamed_function_15(0x194);
  unnamed_function_8(param1,0x20);
  for (local_10 = 0; local_10 < 8; local_10 = local_10 + 1) {
    for (local_14 = 0; local_14 < 4; local_14 = local_14 + 1) {
      *(undefined *)(param2 + local_10 * 4 + local_14) = *(undefined *)(param1 + local_c);
      local_c = local_c + 1;
    }
  }
  return;
}
```

**unnamed_function_15**函数就是srand函数，**seed**就是0x194(转过来就是404)，然后进入**unnamed_function_8**进行打乱

```c
void unnamed_function_8(int param1,int param2)

{
  undefined uVar1;
  int iVar2;
  byte local_11;
  undefined4 i;
  
  if (1 < param2) {
    for (i = 0; i < param2 + -1; i = i + 1) {
      iVar2 = rand();
      iVar2 = i + iVar2 / (0x7fff / (param2 - i) + 1);
      uVar1 = *(undefined *)(param1 + iVar2);
      *(undefined *)(param1 + iVar2) = *(undefined *)(param1 + i);
      *(undefined *)(param1 + i) = uVar1;
    }
  }
  return;
}
```

先生成一个规定范围的伪随机数，然后进行字符顺序打乱

回到**unnamed_function_9**函数，然后对字符进行分组处理

最后进到**unnamed_function_11**函数中进行异或加密，

```c
void unnamed_function_11(int param1,int param2)

{
  int iVar1;
  uint uVar2;
  undefined4 local_1c;
  byte local_15;
  byte local_9;
  
  iVar1 = (int)*(char *)(param2 + iRam00011200) >> 4;
  uVar2 = (int)*(char *)(param2 + iRam00011200) & 0xf;
  iRam00011200 = iRam00011200 + 1;
  unnamed_function_10(0x10ea0,(int)*(char *)(iVar1 * 0x10 + 0x10da0 + uVar2));
  for (local_1c = 0; local_1c < 4; local_1c = local_1c + 1) {
    *(byte *)(param1 + local_1c) =
         *(byte *)(param1 + local_1c) ^ *(byte *)(iVar1 * 0x10 + local_1c * 0x11 + uVar2 + 0x10ea0);
    *(byte *)(param1 + local_1c) = *(byte *)(param1 + local_1c) ^ *(byte *)(local_1c + 0x11020);
  }
  return;
}
```

对传进来的key，分别取高四位和低四位，作为横坐标和纵坐标，在SboxAes数组中取数，给到一个新的数组，然后再将这个数组和和SboxSm4数组进行异或，得到加密之后的数组，再和flag进行第一次异或，接着flag再和未异或处理之前的key进行第二次异或加密，完成所有加密，最后和密文进行比对。

密文的地址是**0x10fa0**，

![image-20250413113825136](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250413113825136.png)

下面就是解密脚本了

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
unsigned char SboxAes[16][16] = {
	{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
	{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
	{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
	{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
	{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
	{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
	{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
	{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
	{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
	{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
	{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
	{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
	{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
	{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
	{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
	{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};
int SboxSm4[256] = {
	0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
	0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
	0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
	0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
	0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
	0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
	0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
	0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
	0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
	0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
	0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
	0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
	0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
	0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
	0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
	0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

int keyIndex = 0;
char realKey[9] = "TGCTF404";

void xor_box(int* sbox, char keyChar) {
	for (int i = 0; i < 256; i++) {
		sbox[i] ^= keyChar;
        sbox[i] &= 0xFF;
	}
}

void decode(int* group, char* key) {
    char Char = key[keyIndex++];
    int r = Char >> 4;
    int l = (Char & 0x0F);
    char keyChar = SboxAes[r][l];

    xor_box(SboxSm4, keyChar);

    for (int i = 0; i < 4; i++) {
        group[i] ^= SboxSm4[(r + i) * 16 + (l + i)];
        group[i] ^= realKey[i];
    }
}

int main() {
    char flag[33] = { 0 };
    char key[9] = "TGCTF404";
    int index = 0;
    srand(404);
    int enc[8][4] = {{0x84, 0x1c, 0x6b, 0xf7},
                    {0x49, 0x22, 0xd6, 0x42 },
                    {0x50, 0x7b, 0x42, 0xf4 },
                    {0x46, 0xa9, 0x83, 0x62 },
                    {0xd1, 0x32, 0x80, 0x42 },
                    {0x6a, 0x10, 0xa3, 0xf2 },
                    {0xe2, 0xb8, 0x0b, 0x76 },
                    {0xb0, 0xdc, 0x02, 0x51 }};
    for (int i = 0; i < 8; i++) {
        key[i] = (key[i] ^ 0x51) & 0xFF;
        printf("%02x ", key[i]);
    }
    printf("\n");

    for (int i = 0; i < 8; i++) {
        decode(enc[i], key);
    }

    for (int i = 0; i < 8; i++) {
		for (int j = 0; j < 4; j++) {
            flag[index++] = enc[i][j] & 0xFF;
		}
	}
    
    int n = 32;
    for (int i = 0; i < n - 1; i++) {
			int j = i + rand() / (0x7fff / (n - i) + 1);
            printf("%d ", j);
	}
    printf("\n");
    printf("%s", flag);
    return 0;
}
```

```python
enc = "Z49H539c{--6}d4888bTUCf8NeFe--e9"
index = [1, 24, 28, 24, 16, 25, 22, 29, 29, 12,
         17, 19, 31, 13, 18, 19, 30, 31, 27, 25,
         24, 30, 29, 25, 28, 27, 29, 27, 30, 29, 30]
enc_list = list(enc)
for i in range(len(index) - 1, -1, -1):  # 从最后一个交换开始
    j = index[i]
    enc_list[i], enc_list[j] = enc_list[j], enc_list[i]
print("".join(enc_list))
```

**HZNUCTF{f898-de85-46e-9e43-b9c8}**
