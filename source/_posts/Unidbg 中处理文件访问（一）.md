---
title: Unidbg 中处理文件访问(一)
tags: [Unidbg]
categories: Unidbg学习
---

# Unidbg 中处理文件访问（一）

### 一、引言

补文件访问在 Unidbg 补环境这项工作里的重要性仅次于补 JNI 环境，它有两个主要特征：

**一是出现频率高**：
它的出现频率远高于补系统调用、补库函数、补虚拟模块这些情况，仅次于 JNI 调用。信息获取和环境检测都会大量使用文件访问。

**二是容易被补漏**：
Unidbg 对文件访问提供了很好的监控和打印，所谓容易补漏，主要是使用者的问题。因为安卓碎片化严重、版本多、权限管理混乱等等原因，因为即使在真实 Android 环境里，访问某个文件没成功也是很常见的事，因此开发上会做大量的兼容处理。换句话说，大部分文件补了最好，不补也不一定有事。因此许多 Unidbg 的使用者走向了极端——完全不关注文件访问，这确实省时省力，而且 80% 样本来说没有影响。但是，在 20% 的样本和场景里会出问题，而且往往越难的样本越会出问题。

因此学号怎么补文件访问还是挺重要的，本篇就是系统地讲这个问题。



### 二、概述

文件访问最主要服务于环境检测和信息收集，举例如下。

- 访问 /proc/self/maps 检测 frida/xposed 等模块。
- 访问 /proc/net/tcp 检测 frida/ida server 默认端口。
- 访问 /proc/self/cmdline 确认在自身进程内。
- 访问 apkfile 做签名校验，解析资源文件等。
- 访问 /xbin/su 检测 root。
- 访问 data/data/package/xxx 读取自身有关文件

Unidbg 通过文件处理器处理文件。默认的文件处理器是 AndroidResolver，我们可以在它的 resolve 方法里处理样本发起的文件访问。

```Java
//source:src/main/java/com/github/unidbg/linux/android/AndroidResolver.java
    @Override
public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String path, int oflags) {
    // 相关逻辑，此处省略
    return null;
}
```

在这里写代码可不是一个好方案，出于两方面原因：

- 可移植性差：AndroidResolver 属于 Unidbg 源码的一部分，修改 AndroidResolver 使其失去了灵活性。如果想迁移项目，需要对整个Unidbg 环境打包。
- 环境混乱：我们一般会在 Unidbg 环境里处理多个样本，它们都有文件访问的需求，对于同一个文件，不同样本的预期返回不一定相同，比如 /proc/self/cmdline 查看包名，在 AndroidResolver 中难以做区分。

Unidbg 并不会让我们陷入泥潭，在文件处理上它采用了责任链模式的设计。用户可以自定义一个或多个文件处理器，当文件访问发生时，多个文件处理器都有机会处理该文件访问，直到其中某个对它处理成功，或最终失败返回为止。责任链模式将多个文件处理器串成链，然后让文件访问在链上传递。

![img](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1663979960314-954f455b-b2bc-4d52-8b40-1111cc987bef.png)

先依次进入用户自定义的 IOResolver A 和 B ，然后就是 AndroidResolver，最后是虚拟文件系统。如果文件访问在较早的某处得到了处理，那就会直接返回。图例所对应的代码如下。

```Java
protected final FileResult<T> resolve(Emulator<T> emulator, String pathname, int oflags) {
    FileResult<T> failResult = null;
    // 依次进入每个文件解析器，以期得到处理
    for (IOResolver<T> resolver : resolvers) {
        FileResult<T> result = resolver.resolve(emulator, pathname, oflags);
        if (result != null && result.isSuccess()) {
            emulator.getMemory().setErrno(0);
            return result;
        } else if (result != null) {
            if (failResult == null || !failResult.isFallback()) {
                failResult = result;
            }
        }
    }
    if (failResult != null && !failResult.isFallback()) {
        return failResult;
    }
	// 虚拟文件系统
    FileResult<T> result = emulator.getFileSystem().open(pathname, oflags);
    if (result != null && result.isSuccess()) {
        emulator.getMemory().setErrno(0);
        return result;
    }

   // 一些杂项路径判断和处理，此处省略
    
    return failResult;
}
```

Unidbg 在这里的设计也并非完美，一些特殊以及杂项文件的处理没有设计对应的文件处理器，而是较为零散的放在各处。事实上，将它们重构为一个 procFileIOResolver 会更合理，感兴趣的读者可以去做尝试。

```Java
if (("/proc/" + emulator.getPid() + "/fd").equals(pathname) || "/proc/self/fd".equals(pathname)) {
    return createFdDir(oflags, pathname);
}
if (("/proc/" + emulator.getPid() + "/task/").equals(pathname) || "/proc/self/task/".equals(pathname)) {
    return createTaskDir(emulator, oflags, pathname);
}
```

上面我们从一个比较高的视角观察了 Unidbg 中文件访问的处理流程，接下里进入细节，可不能眼高手低。首先是定义和添加文件处理器的具体写法，**addIOResolver** 用于添加一个文件处理器对象，将如下代码放在早于 **loadLibrary** 的时机即可生效。

```Java
emulator.getSyscallHandler().addIOResolver(new IOResolver<AndroidFileIO>() {
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        System.out.println("file open:"+pathname);
        return null;
    }
});
```

有时候我们会让目标类实现 IOResolver 接口，那么就是 addIOResolver(this)。

```Java
package com.test3;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class TEST3 extends AbstractJni implements IOResolver<AndroidFileIO> {
    private final AndroidEmulator emulator;
    private final DvmClass LibBili;
    private final VM vm;

    public TEST3() {
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("tv.danmaku.bili")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("D:\\Compilation_Enviroment\\unidbg-master\\unidbg-android\\src\\test\\java\\com\\test3\\bilibili.apk"));
        vm.setJni(this);
        vm.setVerbose(true);

        // add
        emulator.getBackend().registerEmuCountHook(10000); // 设置执行多少条指令切换一次线程
        emulator.getSyscallHandler().setVerbose(true);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);

        emulator.getSyscallHandler().addIOResolver(this);
        //加载Dalvik的模块
        DalvikModule dm = vm.loadLibrary("bili", true);
        //加载目标类
        LibBili = vm.resolveClass("com.bilibili.nativelibrary.LibBili");
        dm.callJNI_OnLoad(emulator);
    }

    public static void main(String[] args) {
        TEST3 test3 = new TEST3();
    }

    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        System.out.println("lilac open: " + pathname);
        return null;
    }


}
```

在处理很复杂的样本时，我们希望逻辑分离，那么可以把 IOSresolver 从主类中摘出去。

```Java
package com.test3;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;

public class BiliIOResolver implements IOResolver<AndroidFileIO> {
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        System.out.println("file open:"+pathname);        
        return null;
    }
}
```

主类代码

```Java
package com.test3;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class TEST3 extends AbstractJni{
    private final AndroidEmulator emulator;
    private final DvmClass LibBili;
    private final VM vm;

    public Bili() {
        emulator = AndroidEmulatorBuilder.for32Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .build();
        emulator.getBackend().registerEmuCountHook(10000); // 设置执行多少条指令切换一次线程
        emulator.getSyscallHandler().setVerbose(true);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/bili/bili.apk"));
        vm.setVerbose(true);
        vm.setJni(this);

        emulator.getSyscallHandler().addIOResolver(new BiliIOResolver());

        DalvikModule dm = vm.loadLibrary("bili", true);
        LibBili = vm.resolveClass("com.bilibili.nativelibrary.LibBili");
        dm.callJNI_OnLoad(emulator);
    }

    public void calla(){
        String appkey = LibBili.callStaticJniMethodObject(emulator, "a(Ljava/lang/String;)Ljava/lang/String;", "android").getValue().toString();
        System.out.println("result:"+appkey);
    }


    public static void main(String[] args) {
        TEST3 test3 = new TEST3();
        test3.calla();
    }
}
```

添加多个自定义文件处理器的场景里(比如处理某公司旗下的多个样本，它们在多数文件访问上类似，但少部分需要各自处理)，需要注意后添加的优先级更高。

```Java
/**
 * 后面添加的优先级高
 */
void addIOResolver(IOResolver<T> resolver);
```

比如下面的逻辑里，文件访问会首先经过B，其次才是A

```Java
emulator.getSyscallHandler().addIOResolver(new IOResolver<AndroidFileIO>() {
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        System.out.println("Resolver A");
        return null;
    }
});

emulator.getSyscallHandler().addIOResolver(new IOResolver<AndroidFileIO>() {
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        System.out.println("Resolver B");
        return null;
    }
});
```

自定义以及添加文件处理器需要关注的内容就这么多，接下来是具体的文件处理。



### 三、文件访问基本处理

这是本篇的主要内容，也是补环境的实际指导。如果想学好它，需要意识到它的知识由三部分构成。

![image.png](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1663983989813-a3022bde-395c-4da8-b671-e1e60033846e.png)

举个例子，我们设置了自定义文件处理器，打印样本所访问的文件，假如日志里出现了下面这么一行

```shell
file open:/proc/sys/kernel/random/boot_id
```

Linux/Android 文件系统的知识：boot_id 文件在开机时生成，在设备关机前不会改变内容。我们将这个文件从真机上 push 出来

对业务的经验：boot_id 常用于构建设备指纹或单纯的信息采集，需要补它。

Unidbg 对应的实现和映射：像下面这样补它

```Java
emulator.getSyscallHandler().addIOResolver(new IOResolver<AndroidFileIO>() {
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        //参数二: 文件路径
        //参数三: 操作文件标志
        switch (pathname){
            case "/proc/sys/kernel/random/boot_id":{
                return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, new File("unidbg-android/src/test/resources/dewu/cpu/boot_id"), pathname));
            }
        }
        return null;
    }
});
```

我们主要讲解第一部分，也会适时补充第二、三部分的内容。先看代码，我们用switch case 对 pathname 做判断，也对 boot_id 做处理，return 语句看起来有些复杂，我们拆解一下。

最外层是 **FileResult.<AndroidFileIO>success**，我们可以返回任意 AndroidFileIO 类型的文件，这么说有点怪，这是因为 Unidbg 是一个 Android/IOS 双端的 Native 模拟器，除了 AndroidFileIO 还有对应于 IOS 的DarwinFileIO，所以由此限制。

对文件访问有 success、failed、fallback 三种处理

- success 表示文件顺利访问，参数是 NewFileIO。
- failed 表示文件访问失败，参数是 error 错误码。
- fallback 表示回退、降级，只有在其他处理器无法处理对该文件的访问时，才由 fallback 指定的文件 IO 来处理。

第一种使用最多，只有文件访问的意图正常——信息收集，我们都很乐意正常予以返回。因为我们希望程序收集到足够多且内容合理的设备信息，以顺利执行完函数以及规避简单风控。

SimpleFileIO 时最常用的 IO 类型，它代表普通文件，上面补 boot_id 就用的它。resolve 所提供的 oflags 和 path 原封不动的传给它，file是从真机 pull 出来的 boot_id 文件。

```Java
public SimpleFileIO(int oflags, File file, String path) {
    super(oflags);
    this.file = file;
    this.path = path;

    if (file.isDirectory()) {
        throw new IllegalArgumentException("file is directory: " + file);
    }
    if (!file.exists()) {
        throw new IllegalArgumentException("file not exists: " + file);
    }
}
```

读者可能会像一个问题，boot_id 在一定程度上用于标识设备，那么在生产环境中，我们需要对它做随机化以躲避风控。使用 SimpleFileIO 就不太好处理这个问题，这时候就可以用 ByteArrayFileIO。

```Java
emulator.getSyscallHandler().addIOResolver(new IOResolver<AndroidFileIO>() {
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        System.out.println("Resolver A");
        switch (pathname){
            case "/proc/sys/kernel/random/boot_id":{
                return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags,  pathname, UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)));
            }
        }
        return null;
    }
});
```

ByteArrayFileIO 在 oflags、pathname 上和 SimpleFileIO 无差别，但它接收一个字节数组而非 File 文件，对于灵活补文件内容有很大的帮助。读者也需要知道它的副作用——没办法对文件做写入操作，ByteArrayFileIO 像浮萍漂泊，无根无依。

```Java
@Override
public int write(byte[] data) {
    throw new UnsupportedOperationException();
}
```

如果样本访问的是一个目录呢？这时候就要用 DirectoryFileIO，File 传入文件夹即可。

```Java
case "/data/data/com.sankuai.meituan":{
    return FileResult.<AndroidFileIO>success(new DirectoryFileIO(oflags, pathname, new File("unidbg-android/src/test/resources/meituan/data")));
}
```

但对于文件夹访问而言，使用虚拟文件系统是更好的选择。

使用虚拟文件系统，我们对文件的掌控程度会下降，在补常规文件时不算好办法，但补文件夹算是一个特殊情况。举个例子，如果样本访问本机的 /sysytem/fonts 目录，对所有字体文件做 md5 然后上传。如果用 DirectoryFileIO 补，那么在补了 fonts 文件夹后，还需要用 SimpleFileIO 处理每个字体文件的访问，工作量很大，而使用虚拟文件系统，只要把文件夹对对应位置放好，就可以顺利处理整个逻辑。

需要注意，补文件访问时不要犯低级错误，比如样本访问 proc/version，尽管和 /proc/version 是一回事，但你可不要多了一个斜杠，pathname 字符串匹配找不到了。

80%的情况里，你就会遇到这么点文件访问的需求——从真机中把对应的文件拖出来，用SimpleFileIO、ByteArrayFileIO、DirectoryFileIO 以及虚拟文件系统去处理它。

比如补 apk，在任何情况下，都不应该对访问 apk 忽略不管，因为它往往用于资源读取或签名校验，不补风险很大。

```Java
case "/data/app/com.jingdong.app.mall-jJGgNO9r6uKMLj1ytVwSRw==/base.apk":{
    return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, new File("unidbg-android/src/test/resources/jd/jd.apk"), pathname));
}
```

补 CPU 信息

```Java
// https://bbs.pediy.com/thread-229579-1.htm
case "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq":{
    return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, "1766400".getBytes()));
}
```

补电池信息

```Java
case "/sys/class/power_supply/battery/temp":{
    return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, new File("unidbg-android/src/test/resources/meituan/files/battery/temp"), pathname));
}

case "/sys/class/power_supply/battery/voltage_now":{
    return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, new File("unidbg-android/src/test/resources/meituan/files/battery/voltage_now"), pathname));
}
```

接下来说说 failed，它表示文件访问失败，使用场景其实也不多。因为只要我们什么都不补，AndroidResolver 里没有处理这个文件，虚拟文件系统中也不包含它，那就自动访问失败 + 设置错误码。

但有个情况比较例外——如果文件访问 /data，判断是都有写权限，进而确认设备环境是否 Root 的话，我们需要手动处理。

```Java
case "/data":{
    return FileResult.failed(UnixEmulator.EACCES);
}
```

因为虚拟文件系统会自动生成 data 目录，进而访问成功。错误码列表如下，也可以直接使用看 Linux 的错误码文档进行设置，Unidbg 本就是它的简单映射。

```Java
package com.github.unidbg.unix;

public interface UnixEmulator {

    int EPERM = 1; /* Operation not permitted */
    int ENOENT = 2; /* No such file or directory */
    int ESRCH = 3; /* No such process */
    int EINTR = 4; /* Interrupted system call */
    int EBADF = 9; /* Bad file descriptor */
    int EAGAIN = 11; /* Resource temporarily unavailable */
    int ENOMEM = 12; /* Cannot allocate memory */
    int EACCES = 13; /* Permission denied */
    int EFAULT = 14; /* Bad address */
    int EEXIST = 17; /* File exists */
    int ENOTDIR = 20; /* Not a directory */
    int EINVAL = 22; /* Invalid argument */
    int ENOTTY = 25; /* Inappropriate ioctl for device */
    int ENOSYS = 38; /* Function not implemented */
    int ENOATTR = 93; /* Attribute not found */
    int EOPNOTSUPP = 95; /* Operation not supported on transport endpoint */
    int EAFNOSUPPORT = 97; /* Address family not supported by protocol family */
    int EADDRINUSE = 98; /* Address already in use */
    int ECONNREFUSED = 111; /* Connection refused */

}
```



### 四、环境检测

当样本做环境检测相关的文件访问时，主要检测这些文件是否存在，以及是否有权限

- Root检测（检测su、magisk、riru、检测市面上的 Root 工具）
- 模拟器检测（检测Qemu、检测各家模拟器，比如夜神、雷电、MuMu 等模拟器的文件特征、驱动特征等）
- 危险应用检测（各类多开助手、按键精灵、接码平台）
- 云手机检测（以各种云手机产品为主）
- Hook框架（以Xposed、Substrate、Frida 为主）
- 脱壳机（以 Fart、DexHunter、Youpk三者为主）

我们选择什么都不补就行，因为不管时自定义还是默认的文件处理器，以及虚拟文件系统里，都不会有这样的内容，这正和我们的意。就像下面这样，什么都不补就行了。

![img](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1663992483880-6b2a029e-b619-48e1-9f8c-0b9a690b299d.png)

读者需要自行分辨某个文件访问是否属于此类，如果琢磨不定建议 Google 搜索这个文件的主要用途。



### 五、总结

本篇介绍了 Unidbg 中文件处理的基本逻辑和基本使用，80%的场景中它们已经够用。但如果你想探索剩下的20%，以及更多的原理层的内容，就需要看接下来的数篇。



### 六、参考

[Unidbg 中处理文件访问（一）](https://www.yuque.com/lilac-2hqvv/lfssh8/euffrv?# 《Unidbg 中处理文件访问（一）》)
