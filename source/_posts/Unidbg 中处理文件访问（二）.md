---
title: Unidbg 中处理文件访问(二)
tags: [Unidbg]
categories: Unidbg学习
---

# Unidbg 中处理文件访问（二）

### 一、引言

本文主题是 proc 伪文件系统，请读者先了解它，本篇讨论在 Unidbg 里如何补其中对应的文件。



### 二、概述

proc是一个由内核动态创建和生成的目录，程序通过访问它，获取各种各样的内核信息。首先的问题必然是为什么要把它单独拎出来讲，它和其他文件访问在补环境上有什么差异？我给出两点理由：

- 访问频率高——文件访问中最高频处理的目录
- 容易出错——尽管整体上的处理和普通文件一样，但局部需要特殊处理



#### 2.1 cmdline

/proc/self(pid)/cmdline 用于常看自身进程名，常用于信息收集或检测运行环境是否有异常。比如，有些分析人员喜欢将样本 so 移到自己的 Android demo 中加载调试。关于它有几点需要知道，首先，遇到了它一定要补，它可不是什么无足轻重的文件访问，校验进程名是很重要的代码逻辑；其次，pid 在 Unidbg 中每次运行都会变化，因此硬编码无法顺利匹配下一次运行的 pid，请规范处理。

```Java
// A
if (("/proc/"+emulator.getPid()+"/cmdline").equals(pathname) || ("/proc/self/cmdline").equals(pathname)) {
    // 具体处理逻辑
}

// B
if (pathname.contains("cmdline")) {
    // 具体处理逻辑
}
```

对于涉及到 pid 的其他访问路径，也建议一律这么做。而且假设 Unidbg 访问 **/proc/1234/maps** 或 **/proc/self/maps**，你不应该通过 adb 在同样的位置去找它，因为 Unidbg 和真实环境的 pid 显然没有对应关系，应该通过 **ps | grep packgeName** 找到目标 app 在真机上的 pid，然后去做对应的查看。

最后，对于进程名这个需求，没必要从真机拷贝出对应文件，直接 cat 查看，然后用 **ByteArrayFileIO** 处理就很方便，结尾记得加上 \0，这是 cmdline 的格式规范，不加的话在解析时存在出错的可能性。

```Java
// 查看当前进程名
if (("/proc/"+emulator.getPid()+"/cmdline").equals(pathname) || ("/proc/self/cmdline").equals(pathname)) {
    return FileResult.success(new ByteArrayFileIO(oflags, pathname, "name\0".getBytes()));
}
```



#### 2.2 status

/proc/self(pid)/status 最主要用来检测 tracepid 状态，因此偷懒的话可以像下面这样干

```Java
if (("proc/" + emulator.getPid() + "/status").equals(pathname)) {
    return FileResult.success(new ByteArrayFileIO(oflags, pathname, ("TracerPid: 0").getBytes()));
}
```

这么做并非毫无风险，样本也可能会校验和关注其他字段，所以像下面这样补更规范一些。

```Java
if(pathname.equals("proc/"+emulator.getPid()+"/status")){
    return FileResult.success(new ByteArrayFileIO(oflags, pathname,
            ("Name:   ip.android.view\n" +
            "Umask:  0077\n" +
            "State:  S (sleeping)\n" +
            "Tgid:   "+emulator.getPid()+"\n" +
            "Ngid:   0\n" +
            "Pid:    "+emulator.getPid()+"\n" +
            "PPid:   6119\n" +
            "TracerPid:      0\n" +
            "Uid:    10494   10494   10494   10494\n" +
            "Gid:    10494   10494   10494   10494\n" +
            "FDSize: 512\n" +
            "Groups: 3002 3003 9997 20494 50494 99909997\n" +
            "VmPeak:  2543892 kB\n" +
            "VmSize:  2466524 kB\n" +
            "VmLck:         0 kB\n" +
            "VmPin:         0 kB\n" +
            "VmHWM:    475128 kB\n" +
            "VmRSS:    415548 kB\n" +
            "RssAnon:          144072 kB\n" +
            "RssFile:          267216 kB\n" +
            "RssShmem:           4260 kB\n" +
            "VmData:  1488008 kB\n" +
            "VmStk:      8192 kB\n" +
            "VmExe:        20 kB\n" +
            "VmLib:    239368 kB\n" +
            "VmPTE:      2360 kB\n" +
            "VmPMD:        16 kB\n" +
            "VmSwap:    13708 kB\n" +
            "Threads:        122\n" +
            "SigQ:   0/21555\n" +
            "SigPnd: 0000000000000000\n" +
            "ShdPnd: 0000000000000000\n" +
            "SigBlk: 0000000080001204\n" +
            "SigIgn: 0000000000000001\n" +
            "SigCgt: 0000000e400096fc\n" +
            "CapInh: 0000000000000000\n" +
            "CapPrm: 0000000000000000\n" +
            "CapEff: 0000000000000000\n" +
            "CapBnd: 0000000000000000\n" +
            "CapAmb: 0000000000000000\n" +
            "Seccomp:        2\n" +
            "Speculation_Store_Bypass:       unknown\n" +
            "Cpus_allowed:   07\n" +
            "Cpus_allowed_list:      0-2\n" +
            "Mems_allowed:   1\n" +
            "Mems_allowed_list:      0\n" +
            "voluntary_ctxt_switches:        17290\n" +
            "nonvoluntary_ctxt_switches:     10433").getBytes(StandardCharsets.UTF_8)));
}
```



#### 2.3 net

/proc/net 下的文件一律不要补，有两个理由。

- 一是 Google 禁止普通进程访问该目录，这一规定对 Android 10 以及更高版本均有效，所以我们伪装成高版本，多一事不如少一事，少补几个文件而且无副作用，岂不美哉。
- 二是这个目录主要用于检测环境，比如 IDA/Frida Server 的端口检测。将真机的对应文件一股脑拷贝过来，还可能把风险信息和检测点带过来。

简而言之，允许不补，补了还容易出错，你说该怎么办？其中最常见的下面这几个

```shell
/proc/net/arp
/proc/net/tcp
/proc/net/unix
```



#### 2.4 信息获取

遇见下面这些文件，建议正常补，而且了解每个文件的用途，在生产环境上部分需要随机化。

```shell
/proc/meminfo
/proc/version
/proc/cpuinfo
/proc/stat
/proc/asound/cardX/id
/proc/self/exe
```



#### 2.5 map

/proc/self(pid)/maps 是补 proc 文件访问中最重要的一项，请读者良好处理每一次 maps 访问。因为 maps 访问频率高以及地位特殊，Unidbg 中对它做了专门的处理——如果在自定义 IOResolver 中没有得到处理，会在最后的虚拟文件系统这一块进行如下处理。

```Java
// src/main/java/com/github/unidbg/file/linux/LinuxFileSystem.java
@Override
public FileResult<AndroidFileIO> open(String pathname, int oflags) {
    if ("/proc/self/maps".equals(pathname) || ("/proc/" + emulator.getPid() + "/maps").equals(pathname)) {
        return FileResult.<AndroidFileIO>success(new MapsFileIO(oflags, pathname, emulator.getMemory().getLoadedModules()));
    }

    return super.open(pathname, oflags);
}
```

MapsFileIO 是 Unidbg 所设计的 fakemaps，它反应了 Unidbg 内存环境中的模块信息，即在语义和格式都等价于真实的 maps，如下就是 libmtguard.so 对应的 fakemaps。

```Java
40000000-400cd000 r-xp 00000000 b3:19 0          /data/app/com.sankuai.meituan-1/lib/arm/libmtguard.so
400cd000-400ea000 rw-p 000cd890 b3:19 0          /data/app/com.sankuai.meituan-1/lib/arm/libmtguard.so
400ea000-40104000 r-xp 00000000 b3:19 0          /system/lib/libz.so
40104000-40106000 rw-p 0001ace0 b3:19 0          /system/lib/libz.so
40108000-40190000 r-xp 00002000 b3:19 0          /system/lib/libc++.so
40191000-40197000 rw-p 0008b410 b3:19 0          /system/lib/libc++.so
40197000-40199000 r-xp 00000000 b3:19 0          /system/lib/libdl.so
40199000-4019b000 rw-p 00002edc b3:19 0          /system/lib/libdl.so
4019b000-4020e000 r-xp 00000000 b3:19 0          /system/lib/libc.so
4020e000-4021f000 rw-p 00073f60 b3:19 0          /system/lib/libc.so
4021f000-4023e000 r-xp 00000000 b3:19 0          /system/lib/libm.so
4023f000-40241000 rw-p 00020c5c b3:19 0          /system/lib/libm.so
40241000-40249000 r-xp 00000000 b3:19 0          /system/lib/liblog.so
40249000-4024b000 rw-p 00008d08 b3:19 0          /system/lib/liblog.so
4024b000-40250000 r-xp 00000000 b3:19 0          /system/lib/libstdc++.so
40250000-40252000 rw-p 00005dec b3:19 0          /system/lib/libstdc++.so
```

从客观上讲，这个 maps 确实能处理一些问题。比如样本访问 maps，检测其中是否有 frida / xposed / substrate / magisk / riru 等风险模块，真实 maps 会暴露这些信息，而 Unidbg fakeMaps 很干净、简洁，所以不会有任何问题。

既然 Unidbg 对 maps 做了这样周到的处理，为什么还要关注 maps 呢？请读者考虑 fakeMaps 和真实 maps 的关系，fakeMaps 仅包含按目标模块及其依赖的信息，真实 maps 包含整个进程所涉及的所有模块信息，两者关系如下。
![image-20250808113259123](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250808113259123.png)

因此在内容上，fakeMaps 是真实 maps 的子集，后者包含了许多前者不具备的信息。如果样本试图获取小框以外的信息，就会出问题。

- 比如真实 maps 包含当前进程所对应 apk，可以访问和解析它，做签名校验。
- 比如有些样本会检测安全 SDK 是否已加载，未加载就不提供服务，判断逻辑是 maps 中是否能找到安全 SDK 对应的so。

上面两个逻辑，没法依靠 fakeMaps 实现处理。既然 fakeMaps 有这样的问题，使用真实 maps 会好吗？对于上面两个问题，使用真实 maps 就解决了问题。但在另外一些场景里，fakeMaps 可行，真实 maps 会出问题，下面开始举例。

我们知道，maps 反映了内存布局的详细情况，那么如果样本根据 maps 做内存访问呢？比如检查目标函数所属的 libshell-superv.2019.so 是否被inline hook，又或者遍历内存寻找 frida 等工具的特征字符串等等。maps 所指引的 755118f000-75511d2000 在真实运行环境上，是目标 so 起始的一段内存，但在 Unidbg 环境里，这段内存甚至没有开辟。
![image-20250808113922335](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250808113922335.png)

这就好比拿着上海地图在杭州开车，怎么能不出错呢？因此不管使用真实 maps 还是 fakeMaps，都可以解决一些问题，但又会遭遇另一些问题。

在理论上，建议遇到对 maps 的访问，就对这部分逻辑做算法分析，完全确定其访问意图，然后反向构造合适的 maps 予以返回。

在实践上，可能没法总这么干，因为太费事了，那么建议优先使用真实 maps，如果出现内存异常（这意味着样本在基于真实 maps 做内存访问），就使用fakeMaps。



### 三、参考

[Unidbg 中处理文件访问（二）](https://www.yuque.com/lilac-2hqvv/lfssh8/tadqng?# 《Unidbg 中处理文件访问（二）》)
