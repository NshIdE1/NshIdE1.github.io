---
title: 抽象RC4
tags: [CTF, RE, WritesUp, 抽象]
categories: CTF
---

# 抽象RC4

一道很逆天的题目...

ida直接分析

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int Seed; // eax
  int v5[2]; // [rsp+2Ch] [rbp-14h] BYREF
  unsigned int n0x2F; // [rsp+34h] [rbp-Ch]
  int n3; // [rsp+38h] [rbp-8h]
  int n15; // [rsp+3Ch] [rbp-4h]

  _main(argc, argv, envp);
  n15 = 15;
  Seed = time(0i64);
  srand(Seed);
  puts("You want my treasure? You can have it all if you want it. Go find it! I hid the treasure chest in the program");
  puts("Number of remaining steps: 15 | 1 to 3 steps per round | The first one to get to the KEY\n");
  v5[1] = 0;
  while ( n15 > 0 )
  {
    printf("Remaining steps: [%d]\n", (unsigned int)n15);
    do
    {
      printf("Number of steps (1-3): ");
      while ( scanf("%d", v5) != 1 )
      {
        printf("Input error, please re-enter: ");
        while ( getchar() != 10 )
          ;
      }
      if ( v5[0] > 0 && v5[0] <= 3 )
      {
        if ( n15 < v5[0] )
          printf(aNotEnoughSteps, (unsigned int)n15);
      }
      else
      {
        puts(aMustTake13Step);
      }
    }
    while ( v5[0] <= 0 || v5[0] > 3 || n15 < v5[0] );
    n15 -= v5[0];
    printf("* Player walks %d steps, remaining %d\n\n", (unsigned int)v5[0], (unsigned int)n15);
    if ( n15 <= 0 )
    {
      full_decrypt();
      puts("This is your KEY. You deserve it ! !");
      for ( n0x2F = 0; n0x2F <= 0x2F; ++n0x2F )
        printf("%02X", real_key[n0x2F]);
      break;
    }
    n3 = calculate_best_move((unsigned int)n15);
    if ( n3 <= 0 || n3 > 3 )
      n3 = 1;
    if ( n3 > n15 )
      n3 = n15;
    n15 -= n3;
    printf("* The AI takes %d steps, remaining %d\n\n", (unsigned int)n3, (unsigned int)n15);
    if ( n15 <= 0 )
      puts("This treasure does not belong to you. Go back, Boy");
  }
  printf("\nGame over ! ");
  system("pause");
  return 0;
}
```

就是一个类似于之前TPCTF2025的一道题，"搬石头"，可以直接和"AI"对弈，第一步走"3"，然后后面走的每一步都是(4 - x)，x为上一回合中"AI"的步数，然后直接拿到key

![image-20250426221230130](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250426221230130.png)

一开始拿到key不知道有什么用，继续分析程序。在函数窗口看到有rc4_init，rc4_next

![image-20250426221328189](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250426221328189.png)

继续分析

**rc4_init**

```c
__int64 __fastcall rc4_init(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  __int64 result; // rax
  char v4; // [rsp+2h] [rbp-Eh]
  int n255_1; // [rsp+4h] [rbp-Ch]
  int v6; // [rsp+8h] [rbp-8h]
  int n255; // [rsp+Ch] [rbp-4h]

  for ( n255 = 0; n255 <= 255; ++n255 )
    *(_BYTE *)(a1 + n255) = n255;
  v6 = 0;
  for ( n255_1 = 0; n255_1 <= 255; ++n255_1 )
  {
    v6 = ((*(_BYTE *)(n255_1 % a3 + a2) ^ 0x37) + *(unsigned __int8 *)(a1 + n255_1) + v6) % 256;
    v4 = *(_BYTE *)(a1 + n255_1);
    *(_BYTE *)(a1 + n255_1) = *(_BYTE *)(a1 + v6);
    *(_BYTE *)(a1 + v6) = v4;
  }
  *(_DWORD *)(a1 + 260) = 0;
  result = a1;
  *(_DWORD *)(a1 + 256) = *(_DWORD *)(a1 + 260);
  return result;
}
```

**rc4_next**

```c
__int64 __fastcall rc4_next(__int64 a1)
{
  unsigned __int8 v2; // [rsp+Eh] [rbp-2h]
  char v3; // [rsp+Fh] [rbp-1h]

  *(_DWORD *)(a1 + 256) = (*(_DWORD *)(a1 + 256) + 1) % 256;
  *(_DWORD *)(a1 + 260) = (*(_DWORD *)(a1 + 260) + *(unsigned __int8 *)(a1 + *(int *)(a1 + 256))) % 256;
  v3 = *(_BYTE *)(a1 + *(int *)(a1 + 256));
  *(_BYTE *)(a1 + *(int *)(a1 + 256)) = *(_BYTE *)(a1 + *(int *)(a1 + 260));
  *(_BYTE *)(a1 + *(int *)(a1 + 260)) = v3;
  v2 = *(_BYTE *)(a1 + (unsigned __int8)(*(_BYTE *)(a1 + *(int *)(a1 + 256)) + *(_BYTE *)(a1 + *(int *)(a1 + 260))));
  return (16 * v2) | (unsigned int)(v2 >> 4);
}
```

但是这两函数不被任何函数调用，但是我们在分析**full_decrypt()**函数时，在查看**encrypted_key**数组数据时看到一串可疑的数据

![image-20250426221535815](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250426221535815.png)

于是就尝试将这串数据作为密文，程序输出的key作为密钥按照程序中rc4的逻辑进行解密，这道题抽象的地方就在于，明明在main函数中看到输出key的格式化是十六进制形式，但是真正在解密的时候却是字符串，逆天...

由于程序的rc4进行了魔改，直接dump下伪代码进行解密

```c
#include <stdio.h>

#define _BYTE unsigned char
#define _DWORD unsigned int
#define _QWORD unsigned long

unsigned char data[48] = {
    0xBB, 0xCA, 0x12, 0x14, 0xD0, 0xF1, 0x99, 0xA7, 0x91, 0x48, 0xC3, 0x28, 0x73, 0xAD, 0xB7, 0x75,
    0x8C, 0x89, 0xCD, 0xDD, 0x2D, 0x50, 0x5D, 0x7F, 0x95, 0xB1, 0xA4, 0x9D, 0x09, 0x43, 0xE1, 0xD2,
    0xE9, 0x66, 0xEA, 0x18, 0x98, 0xC6, 0xCC, 0x02, 0x39, 0x18
};

__int64 __fastcall rc4_init(__int64 a1, __int64 a2, unsigned __int64 a3)
{
    __int64 result; // rax
    char v4; // [rsp+2h] [rbp-Eh]
    int j; // [rsp+4h] [rbp-Ch]
    int v6; // [rsp+8h] [rbp-8h]
    int i; // [rsp+Ch] [rbp-4h]

    for (i = 0; i <= 255; ++i)
        *(_BYTE*)(a1 + i) = i;
    v6 = 0;
    for (j = 0; j <= 255; ++j)
    {
        v6 = ((*(_BYTE*)(j % a3 + a2) ^ 0x37) + *(unsigned __int8*)(a1 + j) + v6) % 256;
        v4 = *(_BYTE*)(a1 + j);
        *(_BYTE*)(a1 + j) = *(_BYTE*)(a1 + v6);
        
        *(_BYTE*)(a1 + v6) = v4;
        //printf("%d,",*(_BYTE*)(a1 + j));
    }

    *(_DWORD*)(a1 + 260) = 0;
    result = a1;
    *(_DWORD*)(a1 + 256) = *(_DWORD*)(a1 + 260);
    return result;
}

__int64 __fastcall rc4_next(__int64 a1)
{
    unsigned __int8 v2; // [rsp+Eh] [rbp-2h]
    char v3; // [rsp+Fh] [rbp-1h]

    *(_DWORD*)(a1 + 256) = (*(_DWORD*)(a1 + 256) + 1) % 256;
    *(_DWORD*)(a1 + 260) = (*(_DWORD*)(a1 + 260) + *(unsigned __int8*)(a1 + *(int*)(a1 + 256))) % 256;
    v3 = *(_BYTE*)(a1 + *(int*)(a1 + 256));
    *(_BYTE*)(a1 + *(int*)(a1 + 256)) = *(_BYTE*)(a1 + *(int*)(a1 + 260));
    *(_BYTE*)(a1 + *(int*)(a1 + 260)) = v3;
    v2 = *(_BYTE*)(a1 + (unsigned __int8)(*(_BYTE*)(a1 + *(int*)(a1 + 256)) + *(_BYTE*)(a1 + *(int*)(a1 + 260))));
    return (16 * v2) | (unsigned int)(v2 >> 4);
}

unsigned char key[0x200];

int main(){
    unsigned char real_key[] = "EC3700DFCD4F364EC54B19C5E7E26DEF6A25087C4FCDF4F8507A40A9019E3B48BD70129D0141A5B8F089F280F4BE6CCD";
    rc4_init((long long)key, (long long)real_key, sizeof(real_key)-1);

    for (int i = 0; i < 42; i++) {
        data[i] ^= rc4_next((long long)key);
    }
    printf("%s", data);
    return 0;
}
```

**flag{8263b6c6-094d-4bd8-bbc2-b63ab34e8db7}**