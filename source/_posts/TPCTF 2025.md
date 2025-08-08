---
title: TPCTF 2025
tags: [CTF, RE, WritesUp]
categories: CTF
---

# TPCTF 2025

### chase

一道nes游戏题，刚开始尝试反编译，然后拿到asm文件，但是数量太大，并且逻辑抽象，用Ghidra能反编译一些，但是逻辑感觉完全无用，就只能选择游戏作弊通关拿flag这条路了，用的模拟器是Fceus64模拟器，一些基本的用法详见文章https://zhuanlan.zhihu.com/p/184862425

直接修改关卡目标分数，全部改成0，该分数地址在0x83，当前分数在0x84，通关之后拿到第一部分flag

![fc33a2f0519be663231dbb9c20950e5](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/fc33a2f0519be663231dbb9c20950e5.png)

**TPCTF{D0_Y0U_L1KE_**

然后在Debug选项中点击PPU Viewer，可以找到第三部分的flag

![image-20250309132713692](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250309132713692.png)

**ON_Y0UR_N3S?}**

> PPU Viewer用于查看PPU内存中的图案表（Pattern Tables）、名称表（Name Tables）等图形数据。那么按道理应该pt2的flag也会在这里看到，看不到的原因可能是因为被黑色覆盖掉了，所以我们可以先找到pt1的地址，然后将pt2的内容覆盖到pt1上进行显示。

然后我们在PPU Viewer窗口，当我们的光标放在某个字符上时，下方会显示例如，放在F上，Title：$26

> 在PPU Viewer中，“Title: $26”主要用于标识PPU内存中的特定图形数据区域，帮助开发者调试和管理图形资源。

然后我们找到FLAG分别对应的值

**F: 26 L: 2C A: 21 G: 27**

010editor打开进行搜索，找到两部分

![image-20250309133453869](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250309133453869.png)

![image-20250309133520772](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250309133520772.png)

将这两部分数据进行替换位置，然后保存玩通关就有pt2了

![image-20250309135006583](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250309135006583.png)

**PLAY1N9_6@M3S_**

拿到flag：**TPCTF{D0_Y0U_L1KE_PLAY1N9_6@M3S_ON_Y0UR_N3S?}**

--------------------------------------------------------------------------------------------------------------------------





### portable

这题应该是全场re最简单的题了，就是一个异或，ida64打开，程序主逻辑在sub_407F30函数，

检查flag长度

![image-20250309142059081](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250309142059081.png)

![image-20250309142420270](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250309142420270.png)

动调跟着这个函数完整的走了一圈下来，发现应该就是这个异或，然后赛博厨子直接出，没写脚本，写脚本的时候发现后半部分不可见，应该因为不是英文的原因吧

![6b43afc54631106daa3e4b398d40793](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/6b43afc54631106daa3e4b398d40793.png)

拿到flag

-------------------------------------------------------------------------------------------------------------------------



### stone_game

ios，是python写的，依旧使用**pyinstxtractor.py**解包，然后分析里面的主函数逻辑和库函数，主函数所在的pyd可以用这个网站进行反编译https://pylingual.io/，但是库函数不行，但也好在这个题和python逆向没多大关系，主要还是玩游戏通关，就是移石头的益智游戏，根据测试，一次最多只能一口气移完四堆石头，否则就会报错，然后要赢100轮，可以手搓也可以pwntools写脚本自动化去打，但是也得找到一个通杀且步骤不复杂的办法，就是每一轮开始，都直接把前四堆的石头全部移完，然后AI会在剩下三堆中任意选一堆一口气移完（别问我为什么，他算法就是这么写的），然后第二手我们把剩下两堆（不为零的两堆），全部移走n-1个，n即为每堆石头的个数，然后AI就会在这两堆中任选一堆移走1个，我们再移走最后一个就win了，可以手动去打，也可以自动化，这里也贴上自动化脚本

```python
from pwn import *

context(log_level="debug", arch="amd64", os="linux")
io = remote("1.95.128.179", 3845)
io.sendline()
for i in range(100):
    io.recvuntil(b"Segment 1: ")
    int1 = int(io.recvuntil(b" "))
    print(int1)
    io.recvuntil(b"Segment 2: ")
    int2 = int(io.recvuntil(b" "))
    print(int2)
    io.recvuntil(b"Segment 3: ")
    int3 = int(io.recvuntil(b" "))
    print(int3)
    io.recvuntil(b"Segment 4: ")
    int4 = int(io.recvuntil(b" "))
    print(int4)
    io.recv()
    payload = f"{int1} {int2} {int3} {int4} {0} {0} {0}"
    io.sendline(payload)

    io.recvuntil(b'AI is thinking...\n')
    sleep(2)
    io.recvuntil(b"Segment 5: ")
    int5 = int(io.recvuntil(b" "))
    print(int5)
    io.recvuntil(b"Segment 6: ")
    int6 = int(io.recvuntil(b" "))
    print(int6)
    io.recvuntil(b"Segment 7: ")
    int7 = int(io.recvuntil(b" "))
    print(int7)
    if int5 == 0:
        payload = f"{0} {0} {0} {0} {0} {int6-1} {int7-1}"
        io.sendline(payload)
    elif int6 == 0:
        payload = f"{0} {0} {0} {0} {int5-1} {0} {int7-1}"
        io.sendline(payload)
    elif int7 == 0:
        payload = f"{0} {0} {0} {0} {int5-1} {int6-1} {0}"
        io.sendline(payload)

    io.recvuntil(b'AI is thinking...\n')
    sleep(2)
    io.recvuntil(b"Segment 5: ")
    int5 = int(io.recv(1),10)
    print(int5)

    io.recvuntil(b"Segment 6: ")
    int6 = int(io.recv(1),10)
    print(int6)

    io.recvuntil(b"Segment 7: ")
    int7 = int(io.recv(1),10)
    print(int7)
    if int5 == 1:
        payload = f"{0} {0} {0} {0} {1} {0} {0}"
        io.sendline(payload)
    elif int6 == 1:
        payload = f"{0} {0} {0} {0} {0} {1} {0}"
        io.sendline(payload)
    elif int7 == 1:
        payload = f"{0} {0} {0} {0} {0} {0} {1}"
        io.sendline(payload)
    io.recvuntil(b'You won this round!')
    sleep(2)
io.interactive()
```

拿到flag

**TPCTF{M0nt3_C4rl0_S34rch_1s_4w3s0m3_f0r_g4m3s}**

--------------------------------------------------------------------------------------------------------------------------



### magicfile

（赛后复现）

闹麻了，纯纯misc，010editor打开，然后找到正确提示，

![image-20250310133232786](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250310133232786.png)

然后顺着往上找，就能找到flag，每个字符是以单字节的形式存放

![image-20250310133336843](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250310133336843.png)

![image-20250310133407295](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250310133407295.png)

依次类推，拿到flag

**TPCTF{YoU_AR3_SO_5m@R7_TO_cRACk_Th1$_m@9iC_f1le}**

![image-20250310133501797](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250310133501797.png)

---------------------------------------------------------------------------------------------------------------------------





### LinuxPDF

可以找到项目源码，https://github.com/ading2210/linuxpdf，在pdf的最下方

![image-20250311135453180](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311135453180.png)

可以得知embeded_files是**压缩+base64**的结果

用vscode打开这个pdf，可以看到里面有很多base64编码，并且随便挑一个用赛博厨子解编码都可以发现确实都是zlib，因此可以写个脚本将其中所有base64都进行解码，然后zlib解压缩，完了检查其中是否有**Flag**字样，因为谷歌打开这个pdf会有这个提示输出，然后就可以定位到check逻辑，最后找到的文件是**root/files/00000000000000a9**，然后进行解码，接着解zlib，然后ida9.0进行反编译，其中的逻辑就是一个md5，标准的，但是在加密过程有所改变，29位的flag，第一次是完整的flag进行md5加密，然后第二次是从第二位开始进行md5加密，因此可以写一个脚本进行爆破，也可以自己一位一位hashcat进行爆破

![image-20250311104432120](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311104432120.png)

![image-20250311104516670](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311104516670.png)

![image-20250311104609129](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311104609129.png)

反编译是riscv64，所以得用ida9.0

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // a1
  __int64 v4; // a2

  puts("Flag: ", argv, envp);
  scanf("%29s", &unk_4220);
  for ( dword_4284 = 0; dword_4284 <= 27LL; ++dword_4284 )
    sub_2948((char *)&unk_4220 + dword_4284, (char *)&unk_4008 + 17 * dword_4284);
  puts("Correct", v3, v4);
  return 0;
}
```

解密脚本

```python
from hashlib import md5
from string import printable

s = [0x38, 0xF8, 0x8A, 0x3B, 0xC5, 0x70, 0x21, 0x0F, 0x8A, 0x8D, 0x95, 0x58, 0x5B, 0x46, 0xB0, 0x65, 0x00, 0x83, 0x05, 0x5A, 0xE8, 0x0C, 0xDC, 0x8B, 0xD5, 0x93, 0x78, 0xB8, 0x62, 0x8D, 0x73, 0x3F, 0xCB, 0x00, 0xFA, 0x7D, 0xAF, 0xFB, 0xD7, 0xAC, 0xEC, 0x13, 0xB0, 0x69, 0x5D, 0x93, 0x5A, 0x04, 0xBC, 0x0F, 0x00, 0xC2, 0x9C, 0xC0, 0xFD, 0x38, 0x01, 0xC7, 0xFD, 0xD3, 0x15, 0xC7, 0x82, 0x99, 0x9B, 0xD4, 0xCB, 0x00, 0x2B, 0xA2, 0xD0, 0x1A, 0xF1, 0x2D, 0x9B, 0xE3, 0x1A, 0x2B, 0x44, 0x32, 0x3C, 0x1A, 0x4F, 0x47, 0x00, 0xDD, 0xEE, 0xBA, 0xF0, 0x02, 0x52, 0x7A, 0x9E, 0xAD, 0x78, 0xBD, 0x16, 0x68, 0x45, 0x73, 0xCC, 0x00, 0xBF, 0x95, 0xB8, 0x99, 0x34, 0xA1, 0xB5, 0x55, 0xE1, 0x09, 0x0F, 0xEC, 0xDF, 0xD3, 0xDA, 0x9F, 0x00, 0xB6, 0x42, 0x2C, 0x30, 0xB0, 0x29, 0x38, 0x53, 0x5F, 0x8E, 0x64, 0x8D, 0x60, 0xA8, 0x7B, 0x94, 0x00, 0x08, 0xC1, 0xB7, 0x66, 0x43, 0xAF, 0x8D, 0xD5, 0x0C, 0xB0, 0x6D, 0x7F, 0xDD, 0x3C, 0xF8, 0xED, 0x00, 0x42, 0xD6, 0x97, 0x19, 0xF9, 0x70, 0x88, 0xF0, 0x65, 0x40, 0xF4, 0x12, 0xDC, 0x17, 0x06, 0xFB, 0x00, 0xA1, 0xF2, 0x3D, 0xA6, 0x16, 0x15, 0x40, 0x0E, 0x7B, 0xD9, 0xEA, 0x72, 0xD6, 0x35, 0x67, 0xEB, 0x00, 0x4E, 0x24, 0x6F, 0x0A, 0x5D, 0xD3, 0xCE, 0x59, 0x46, 0x5F, 0xF3, 0xD0, 0x2E, 0xC4, 0xF9, 0x84, 0x00, 0xB8, 0xCF, 0x25, 0xF9, 0x63, 0xE8, 0xE9, 0xF4, 0xC3, 0xFD, 0xDA, 0x34, 0xF6, 0xF0, 0x1A, 0x35, 0x00, 0x2D, 0x98, 0xD8, 0x20, 0x83, 0x5C, 0x75, 0xA9, 0xF9, 0x81, 0xAD, 0x4D, 0xB8, 0x26, 0xBF, 0x8E, 0x00, 0x70, 0x2E, 0xAD, 0x08, 0xA3, 0xDD, 0x56, 0xB3, 0x13, 0x4C, 0x7C, 0x38, 0x41, 0xA6, 0x52, 0xAA, 0x00, 0xD2, 0xD5, 0x57, 0xB6, 0x13, 0x66, 0x2B, 0x92, 0xF3, 0x99, 0xD6, 0x12, 0xFB, 0x91, 0x59, 0x1E, 0x00, 0xE4, 0x42, 0x2B, 0x63, 0x20, 0xED, 0x98, 0x9E, 0x7E, 0x3C, 0xB9, 0x7F, 0x36, 0x9C, 0xBA, 0x38, 0x00, 0x71, 0x80, 0x35, 0x86, 0xC6, 0x70, 0x59, 0xDD, 0xA3, 0x25, 0x25, 0xCE, 0x84, 0x4C, 0x50, 0x79, 0x00, 0x83, 0xB3, 0x71, 0x80, 0x1D, 0x0A, 0xDE, 0x07, 0xB5, 0xC4, 0xF5, 0x1E, 0x8C, 0x62, 0x15, 0xE2, 0x00, 0xB0, 0xD1, 0xB4, 0x88, 0x5B, 0xC2, 0xFD, 0xC5, 0xA6, 0x65, 0x26, 0x69, 0x24, 0x48, 0x6C, 0x5F, 0x00, 0x79, 0x2C, 0x9E, 0x7F, 0x05, 0xC4, 0x07, 0xC5, 0x6F, 0x3B, 0xEC, 0x4C, 0xA7, 0xE5, 0xC1, 0x71, 0x00, 0x38, 0x55, 0xE5, 0xA5, 0xBB, 0xC1, 0xCB, 0xE1, 0x8A, 0x6E, 0xAB, 0x5D, 0xD9, 0x7C, 0x06, 0x3C, 0x00, 0x88, 0x6D, 0x45, 0xE0, 0x45, 0x1B, 0xBB, 0xA7, 0xC0, 0x34, 0x1F, 0xE9, 0x0A, 0x95, 0x4F, 0x34, 0x00, 0x3A, 0x43, 0x7C, 0xBE, 0x65, 0x91, 0xEA, 0x34, 0x89, 0x64, 0x25, 0x85, 0x6E, 0xAE, 0x7B, 0x65, 0x00, 0x34, 0x30, 0x49, 0x67, 0xA0, 0x67, 0x30, 0x8A, 0x76, 0x70, 0x1F, 0x05, 0xC0, 0x66, 0x85, 0x51, 0x00, 0xD6, 0xAF, 0x7C, 0x4F, 0xED, 0xCF, 0x2B, 0x67, 0x77, 0xDF, 0x8E, 0x83, 0xC9, 0x32, 0xF8, 0x83, 0x00, 0xDF, 0x88, 0x93, 0x1E, 0x7E, 0xEF, 0xDF, 0xCC, 0x2B, 0xB8, 0x0D, 0x4A, 0x4F, 0x57, 0x10, 0xFB, 0x00, 0xCB, 0x0F, 0xC8, 0x13, 0x75, 0x5A, 0x45, 0xCE, 0x59, 0x84, 0xBF, 0xBA, 0x15, 0x84, 0x7C, 0x1E, 0x00]

flag = "}"
for j in range(len(s)-17, -1, -17):
    for i in printable:
        text = i + flag
        if md5(text.encode()).hexdigest() == bytes(s[j:j+16]).hex():
            print(text)
            flag = text
            break
```

```
hashcat.exe -a 3 -m 0 cb0fc813755a45ce5984bfba15847c1e ?a}
```

掩码爆破，?a就是任意可见字符。

![image-20250311102552759](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311102552759.png)

**TPCTF{mag1c_RISC-V_linux-PDF}**

---------------------------------------------------------------------------------------------------------------------------



### obfuscator

这题切入点就很奇怪，运行了elf，在根目录tmp文件夹里生成一个.cache文件，记事本或者010editor打开可以发现里面藏了严重混淆的js代码，提取出来，

```js
(function Y4QD(HkYv) {
  const jS0v = Tr5t(
    HkYv,
    bIQv(Y4QD.toString())
  );
  try {
    let DfTv = eval(jS0v);
    return DfTv.apply(null, Aevx);
  } catch (fNVv) {
    var zaOv = 0o203410 - 67316;
    while (zaOv < 0o400155 % 65575)
      switch (zaOv) {
        case 0x3004d % 0o200023:
          zaOv =
            fNVv instanceof SyntaxError
              ? 0o400115 % 0x1001f
              : 0o400157 % 0x10028;
          break;
        case 0o200702 - 0x101b3:
          zaOv = 0o400173 % 65582;
          {
            console.log("Error: the code has been tampered!");
            return;
          }
          break;
      }
    throw fNVv;
  }
  function bIQv(bKnw) {
    let Dhqw = 975342312;
    var XEiw = 0o400141 % 65567;
    {
      let zclw;
      while (XEiw < 0x105a0 - 0o202574) {
        switch (XEiw) {
          case 0o600066 % 0x1000e:
            XEiw = 68656 - 0o206026;
            {
              Dhqw ^=
                (bKnw.charCodeAt(zclw) * (15658734 ^ 0o73567354) +
                  bKnw.charCodeAt(zclw >>> (0x4a5d0ce & 0o320423424))) ^
                835577039;
            }
            break;
          case 0o205050 - 68110:
            XEiw = 131151 % 0o200032;
            zclw++;
            break;
          case 262303 % 0o200041:
            XEiw = zclw < bKnw.length ? 0o400076 % 0x10019 : 68056 - 0o204664;
            break;
          case 0o1000227 % 0x1001d:
            XEiw = 0o203542 - 0x10747;
            zclw = 0x75bcd15 - 0o726746425;
            break;
        }
      }
    }
    let Tzdw = "";
    var v7fw = 65836 - 0o200435;
    {
      let Pu8v;
      while (v7fw < 0o600205 % 0x10022) {
        switch (v7fw) {
          case 0o600146 % 65565:
            v7fw = 0x20036 % 0o200022;
            Pu8v = 0x21786 % 3;
            break;
          case 0o200550 - 0x10156:
            v7fw =
              Pu8v < (0o347010110 & 0x463a71d)
                ? 65836 - 0o200416
                : 0o400151 % 0x10025;
            break;
          case 131158 % 0o200034:
            v7fw = 73639709 % 9;
            {
              const r2aw = Dhqw % (0x10690 - 0o203170);
              Dhqw = Math.floor(Dhqw / (0o600140 % 65560));
              Tzdw +=
                r2aw >= 0o1000136 % 0x10011
                  ? String.fromCharCode(
                      0o212120 - 0x1140f + (r2aw - (0o203434 - 67330))
                    )
                  : String.fromCharCode(0o205536 - 0x10afd + r2aw);
            }
            break;
          case 73639709 % 9:
            v7fw = 67156 - 0o203102;
            Pu8v++;
            break;
        }
      }
    }
    return Tzdw;
  }
  function Tr5t(vZ7t, Pm0t) {
    vZ7t = decodeURI(vZ7t);
    let rU2t = 0x21786 % 3;
    let LhVt = "";
    var nPXt = 0o204622 - 0x1096f;
    {
      let HcQt;
      while (nPXt < 0o200550 - 65860) {
        switch (nPXt) {
          case 0o200360 - 65764:
            nPXt = 0o201010 - 66030;
            {
              LhVt += String.fromCharCode(
                vZ7t.charCodeAt(HcQt) ^ Pm0t.charCodeAt(rU2t)
              );
              rU2t++;
              var jKSt = 0x10186 - 0o200571;
              while (jKSt < 0x103e8 - 0o201717)
                switch (jKSt) {
                  case 0o600114 % 0x10015:
                    jKSt =
                      rU2t >= Pm0t.length
                        ? 0x30066 % 0o200032
                        : 0o400127 % 65567;
                    break;
                  case 67216 - 0o203170:
                    jKSt = 0o600160 % 65565;
                    {
                      rU2t = 0x21786 % 3;
                    }
                    break;
                }
            }
            break;
          case 68506 - 0o205577:
            nPXt = HcQt < vZ7t.length ? 0o1000164 % 65562 : 68056 - 0o204664;
            break;
          case 67636 - 0o204021:
            nPXt = 0o1000227 % 65567;
            HcQt = 0x21786 % 3;
            break;
          case 0x4007a % 0o200030:
            nPXt = 0x3007b % 0o200040;
            HcQt++;
            break;
        }
      }
    }
    return LhVt;
  }
})
```

后面还有很长，就不贴出来了。

然后尝试运行，发现报错提示缺少定义Aevx，定义一下

```js
var Aevx;
```

同时，这个js代码有反篡改的检测，通过Y4QD.toString()获取自身源码生成密钥。若函数被修改，密钥变化导致解密失败，eval执行失败时，检查错误类型。若为SyntaxError(密钥错误导致解密出来的代码有语法错误），判定为篡改，输出Error: the code has been tampered!

可以加入

```js
console.log(Y4QD.toString());
```

将打印出来的内容把后面

```js
const jS0v = Tr5t(HkYv, bIQv(Y4QD.toString()));
```

中的**Y4QD.toString**替换掉。

然后再在后面加上

```js
console.log(jS0v);
```

就拿到jS0v了。注意应该最好在编译器里运行，在终端运行好像有些字符无法输出会以_输出。

```js
(function () {
    function AYnQ() {
        return (IqhF()) + (QIKN())
    }

    function UTeQ() {
        return cypN() + AUkK() + EjQI() + EHOF() + sqiD() + glTI()
    }

    function wVhQ() {
        return (sqiD())[wtgN()]()
    }

    function QQYP() {
        return (+!+[] + (++[+[]][+[]])) + (+[] + !+[])
    }
    HbGI = {};

    function sSbQ() {
        return EjQI() + ceKC() + wVhQ() + ULQN()
    }

    function smPQ() {
        gJRF = [];
        const UnSQ = AUsA();
        const ojJQ = MxyB();
        const QkMQ = seBO();
        const kgDQ = wFNB();
        const MhGQ = MdDK();
        var gdxQ = (196698 % 0o200026); {
            let IeAQ;
            while (gdxQ < (196664 % 0o200011)) {
                switch (gdxQ) {
                case (0x102D0 - 0o201270):
                    gdxQ = (262208 % 0o200014);
                    IeAQ = (0x75bcd15 - 0O726746425);
                    break;
                case (262225 % 0o200017):
                    gdxQ = (0O264353757 % 8); {
                        let kEBN = "";
                        const MFEN = QofD[IeAQ];
                        var gBvN = (0o201510 - 0x1032C); {
                            let ICyN;
                            while (gBvN < (0x4009E % 0o200036)) {
                                switch (gBvN) {
                                case (0x10C4E - 0o206053):
                                    gBvN = (0o1000247 % 0x10023); {
                                        kEBN += UnSQ[ojJQ](MFEN[QkMQ](ICyN) ^ (0O264353757 % 8));
                                    }
                                    break;
                                case (68056 - 0o204674):
                                    gBvN = (0o1000301 % 0x10027);
                                    ICyN = (0x21786 % 3);
                                    break;
                                case (262319 % 0o200045):
                                    gBvN = (0o201344 - 0x102BF);
                                    ICyN++;
                                    break;
                                case (0o600243 % 0x1002A):
                                    gBvN = ICyN < MFEN[kgDQ] ? (262319 % 0o200043) : (0o1000246 % 0x10020);
                                    break;
                                }
                            }
                        }
                        gJRF[MhGQ](kEBN);
                    }
                    break;
                case (0o1000104 % 65549):
                    gdxQ = IeAQ < QofD[kgDQ] ? (131113 % 0o200012) : (0o202652 - 66957);
                    break;
                case (0O264353757 % 8):
                    gdxQ = (0x40058 % 0o200022);
                    IeAQ++;
                    break;
                }
            }
        }
    }

    function cypN() {
        return (typeof ([] + []))[+!+[] + !+[]]
    }

    function EzsN() {
        return ((+([+[
            [!+[] + !+[]] + [+[]]
        ]] + [])[+[
            [+[
                [+[]] + [+[]]
            ] + []][+[]][+!+[]]
        ]]) * (orfJ())) + (+[
            [+[
                [+!+[]] + [+[]]
            ] + []][+[]][+!+[]]
        ])
    }

    function YujN() {
        return (AILL())[kYoO()](AoYK())
    }

    function AwmN() {
        return EbCG() + MVoI() + EvpH() + EjQI()
    }

    function AQZN() {
        return oPdG() + kMXF() + kwnL() + wNTN()
    }
    HbGI.t = ([null] == '');

    function cScO() {
        return ([][gViO()] + [])[cWnK()]
    }

    function wNTN() {
        return (EvpH())[wtgN()]()
    }

    function YOWN() {
        return (AQhE())[wtgN()]()
    }

    function sKNN() {
        return cypN() + oPdG() + YiSE() + wNTN() + oPdG() + kMXF() + kwnL() + wNTN()
    }

    function ULQN() {
        return (AUkK())[wtgN()]()
    }

    function oHHN() {
        return function () {};
    }

    function QIKN() {
        return (UrdN()) + (sCHB())
    }
    var QcyO = [(263359 % 0o200361), (86096 - 0o247517), (0x2935494a % 7), (0x20451009 % 9)];

    function seBO() {
        return gtpB() + UbBI() + AUkK() + cypN() + kwnL() + sqiD() + EHOF() + AsjH() + ULQN() + cOZH() + wVpG()
    }

    function MZrO() {
        return (++[+[]][+[]]) + ((QQYP()) * (+([+[
            [!+[] + !+[]] + [+[]]
        ]] + [])[+[
            [+[
                [+[]] + [+[]]
            ] + []][+[]][+!+[]]
        ]]))
    }

    function obvO() {
        return UXxC() + EHOF() + EDDJ() + wNTN()
    }

    function IWlO() {
        return gZtK() + EHOF() + EHOF() + ofGK() + IaxK() + kAyH() + ETfO() + EDDJ()
    }

    function kYoO() {
        return wVpG() + sqiD() + QoXM() + wVpG() + cypN() + MVoI() + EjQI() + EvpH()
    }

    function ETfO() {
        return (IGJJ()) + []
    }

    function gViO() {
        return AQhE() + MVoI() + EjQI() + EHOF()
    }
    var gpWO = [(0o217620 - 0x11F2B), (0x3015A % 0o200121), (0o400345 % 65597), (0o216716 - 73057), (73446 - 0o217165)];

    function IqZO(cmQO, EnTO, YiKO) {
        let AkNO = "";
        var UfEO = (0o205120 - 0x10A3A); {
            let whHO;
            YWkQ: while (UfEO < (0x10E74 - 0o207117)) {
                switch (UfEO) {
                case (0o400136 % 0x1001D):
                    UfEO = (0o400124 % 65561); {
                        var YGIL = (262237 % 0o200017);
                        while (YGIL < (131179 % 0o200043)) switch (YGIL) {
                        case (66616 - 0o202024):
                            YGIL = (0x20075 % 0o200050);
                            break YWkQ;
                        case (0o400075 % 0x1000E):
                            YGIL = whHO >= cmQO.length ? (0x400B4 % 0o200044) : (0x1073A - 0o203425);
                            break;
                        }
                        AkNO += cmQO[whHO];
                    }
                    break;
                case (0o600074 % 0x10009):
                    UfEO = whHO < EnTO + (YiKO === undefined ? cmQO.length : YiKO) ? (196737 % 0o200037) : (0x11158 - 0o210463);
                    break;
                case (0o205240 - 68222):
                    UfEO = (0x3005D % 0o200024);
                    whHO++;
                    break;
                case (0o205120 - 68154):
                    UfEO = (0x107BC - 0o203633);
                    whHO = EnTO;
                    break;
                }
            }
        }
        return AkNO;
    }
```

后面还很长，就不贴出来了。

![image-20250311212616259](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311212616259.png)

这个js将被混淆的字符串QofD解混淆成为字符串gJRF。然后在代码的后半段下个断点，调试就能提取到。

![image-20250311212828711](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311212828711.png)

右键复制值，提取出来

![image-20250311212913596](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311212913596.png)

可以看到有大量的base64编码结果，赛博厨子解码一下，然后识别出是gzip压缩，解压缩一下

![image-20250311213001529](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311213001529.png)

解压缩后发现是wasm

![image-20250311213024199](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311213024199.png)

下载下来。binwalk发现有AES加密

![image-20250311213244008](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311213244008.png)

然后也尝试过编译成.c，但是也还是没分析出什么，最后010打开，搜Flag

![image-20250311213534042](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250311213534042.png)

看到密文，key，iv，以及一个mask，上网搜索之后知道这是带mas掩码的AES加密，把key和iv分别和这个mask异或之后，再CBC模式解AES即可。

![7cb32bd85a16d0a96f9c120cd40a131](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/7cb32bd85a16d0a96f9c120cd40a131.png)

拿到flag：**TPCTF{m47r3shk4_h4ppy_r3v3r53_g@_w45m}**

---------------------------------------本题参照SU两位师傅写的wp复现写的wp----------------------------
