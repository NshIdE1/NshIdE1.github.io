---
title: 从实践中学习unidbg使用(三)
tags: [Unidbg]
categories: Unidbg学习
---

# 从实践中学习unidbg使用(三)

### 一、引言

本篇中的APK详见参考文章中

目标APK：right573.apk

目标方法实现：libnet_crypto.so

本篇将开始讨论补环境。



### 二、任务描述

JADX反编译right573.apk，找到com.izuiyou.network，我们关注于NetCrypto类里的sign方法，它是一个静态方法。

```Java
package com.izuiyou.network;

import android.app.ContextProvider;
import com.meituan.robust.ChangeQuickRedirect;
import com.meituan.robust.PatchProxy;
import com.meituan.robust.PatchProxyResult;
import defpackage.we5;

/* loaded from: classes4.dex */
public class NetCrypto {
    public static ChangeQuickRedirect changeQuickRedirect;

    static {
        we5.a(ContextProvider.get(), "net_crypto");
        native_init();
    }

    public static String a(String str, byte[] bArr) {
        String str2;
        PatchProxyResult proxy = PatchProxy.proxy(new Object[]{str, bArr}, null, changeQuickRedirect, true, 47387, new Class[]{String.class, byte[].class}, String.class);
        if (proxy.isSupported) {
            return (String) proxy.result;
        }
        String sign = sign(str, bArr);
        if (str.contains("?")) {
            str2 = "&sign=" + sign;
        } else {
            str2 = "?sign=" + sign;
        }
        return str + str2;
    }

    public static native byte[] decodeAES(byte[] bArr, boolean z);

    public static native byte[] encodeAES(byte[] bArr);

    public static native String generateSign(byte[] bArr);

    public static native String getProtocolKey();

    public static native void native_init();

    public static native boolean registerDID(byte[] bArr);

    public static native void setProtocolKey(String str);

    public static native String sign(String str, byte[] bArr);
}
```

这段代码主要负责处理网路通信中的加解密和签名相关逻辑。它结合了原生方法(通过native关键字)以及美团的热修复框架Robust。主要方法就是a方法。这是一个用于在URL上拼接签名的工具方法，先通过PathProxy检查是否需要被热更新替换。否则执行默认逻辑：①调用原生方法sign(str, bArr)生成签名；②判断URL中是否已有参数 ? ，然后拼接sign参数返回。这个类的主要用途就是加解密网络数据；为URL或请求生成签名；确保数据完整性和防篡改；支持热更新，允许在不重新发布APK的情况下修复方法逻辑；借助原生库提升加密效率或安全性。

先用Frida附加目标进程做主动调用，可参考如下代码

```js
function callSign(){
  Java.perform(function() {
    function stringToBytes(str) {
      var javaString = Java.use('java.lang.String');
      return javaString.$new(str).getBytes();
    }

    let NetCrypto = Java.use("com.izuiyou.network.NetCrypto");
    let arg1 = "hello world";
    let arg2 = "V I 50";
    let ret = NetCrypto.sign(arg1, stringToBytes(arg2));
    console.log("ret:"+ret);
  })
}
callSign();
```

输出是

```shell
ret:v2-b94195d5f3c2ad3a876f13346fa283a0
```

本篇的目标就是使用Unidbg复现对sign的调用。



### 三、初始化

在Unidbg的unidbg-android/src/test/java下新建包和类。

```Java
package com.test2;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class TEST2 extends AbstractJni {
    private final AndroidEmulator emulator;
    private final DvmClass NetCrypto;
    private final VM vm;

    public TEST2() {
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("cn.xiaochuankeji.tieba")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("D:\\Compilation_Enviroment\\unidbg-master\\unidbg-android\\src\\test\\java\\com\\test2\\right573.apk"));
        vm.setJni(this);
        vm.setVerbose(true);
        DalvikModule dm = vm.loadLibrary("net_crypto", true);
        NetCrypto = vm.resolveClass("com.izuiyou.network.NetCrypto");
        dm.callJNI_OnLoad(emulator);
    }

    public static void main(String[] args) {
        TEST2 test = new TEST2();
    }


}
```

由于样本目录下只包含armeabi-v7a的动态文件，因此只能选择32位，运行代码，发现报错。

```shell
[10:34:53 630]  INFO [com.github.unidbg.linux.AndroidElfLoader] (AndroidElfLoader:481) - libnet_crypto.so load dependency libandroid.so failed
JNIEnv->FindClass(com/izuiyou/network/NetCrypto) was called from RX@0x12049fc5[libnet_crypto.so]0x49fc5
JNIEnv->RegisterNatives(com/izuiyou/network/NetCrypto, RW@0x121c9010[libnet_crypto.so]0x1c9010, 8) was called from RX@0x12049fd7[libnet_crypto.so]0x49fd7
RegisterNative(com/izuiyou/network/NetCrypto, native_init()V, RX@0x1204a069[libnet_crypto.so]0x4a069)
RegisterNative(com/izuiyou/network/NetCrypto, encodeAES([B)[B, RX@0x1204a0b9[libnet_crypto.so]0x4a0b9)
RegisterNative(com/izuiyou/network/NetCrypto, decodeAES([BZ)[B, RX@0x1204a14d[libnet_crypto.so]0x4a14d)
RegisterNative(com/izuiyou/network/NetCrypto, sign(Ljava/lang/String;[B)Ljava/lang/String;, RX@0x1204a28d[libnet_crypto.so]0x4a28d)
RegisterNative(com/izuiyou/network/NetCrypto, getProtocolKey()Ljava/lang/String;, RX@0x1204a419[libnet_crypto.so]0x4a419)
RegisterNative(com/izuiyou/network/NetCrypto, setProtocolKey(Ljava/lang/String;)V, RX@0x1204a479[libnet_crypto.so]0x4a479)
RegisterNative(com/izuiyou/network/NetCrypto, registerDID([B)Z, RX@0x1204a4f5[libnet_crypto.so]0x4a4f5)
RegisterNative(com/izuiyou/network/NetCrypto, generateSign([B)Ljava/lang/String;, RX@0x1204a587[libnet_crypto.so]0x4a587)
```

第一行日志提示，libnet_crypto.so文件试图加载libandroid.so这个依赖库，但是没有找到，接下来探究这个问题的原因和解决方案。

首先是原因，前文我们说，Unidbg的So Loader提供了类似Android Linker的处理机制，对所依赖的用户库以及系统库进行加载，这里加载失败的libandroid.so就是一个系统库，它提供了大量的Android相关的功能，比如访问APK的资源文件等等。具体可看这篇[文章]([Android: 在native中访问assets全解析 - willhua - 博客园](https://www.cnblogs.com/willhua/p/9692529.html))。

那么，Unidbg的lib目录下为什么没有包含这个动态库？
![image-20250705111108967](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705111108967.png)

也可以说，Android FrameWork提供了数十上百个动态库，为什么Unidbg只在lib里放了这么几个？这是因为并非所有的So都可以被Unidbg完备的加载和处理。

以当前的libandroid.so为例，它依赖于相当多的类库，其中许多的Android系统、软硬件、大量的系统调用紧密相关。
![img](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1667897135718-a799b44f-812a-40cf-b31f-067eae755f20.png)

这使得Unidbg很难对它们做妥善、完备的处理，因为Unidbg并不是真正完善健全的模拟器，或者说模拟器就很难像真机一样完善。除了libandroid.so外，libstart.so、libjnigraphics.so等库都因为这个原因没法完成加载。因此Unidbg只默认加载了依赖最少，使用又最多的一批库函数。

可是比如libandroid.so这样的系统库出现频率很高，总不能遇到它们就歇火。因此Unidbg提供了一种叫虚拟模块的机制，提供对这些so文件一部分函数的模拟实现。

目前Unidbg提供了libandroid.so、libjnigraphics.so、libmediandk.so三个库的虚拟模块。
![image-20250705112633520](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705112633520.png)

使用它们相当简单，比如此处缺少libandroid.so，只需要在**早于**目标so文件加载的时机，添加下面这行代码即可。

```Java
new AndroidModule(emulator, vm).register(memory);
```

就像下面这样

```Java
    public TEST2() {
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("cn.xiaochuankeji.tieba")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("D:\\Compilation_Enviroment\\unidbg-master\\unidbg-android\\src\\test\\java\\com\\test2\\right573.apk"));
        vm.setJni(this);
        vm.setVerbose(true);

        // 使用libandroid.so虚拟模块
        new AndroidModule(emulator, vm).register(memory);

        DalvikModule dm = vm.loadLibrary("net_crypto", true);
        NetCrypto = vm.resolveClass("com.izuiyou.network.NetCrypto");
        dm.callJNI_OnLoad(emulator);
    }
```

虚拟模块在本质上就是按模块去Hook和实现一些函数，只不过在形式和处理上更优雅，应该说是一个很好的设计。

它也并非万全之策，以libandroid.so为例，AndroidModule虚拟模块里一共实现了下面几个函数。

- AAssetManager_fromJava
- AAsset_close
- AAsset_getBuffer
- AAsset_getLength
- AAsset_read

![image-20250705114440593](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705114440593.png)

和libandroid.so所具有的数百个导出函数相比，只是极小的一部分。
![img](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1667898041325-6e2aa628-67bb-48a2-acc8-bc9d35af4305.png)

即使只考虑已处理的五个函数，它也远称不上完善，只是一种简单的模拟。libjnigraphics.so、libmediandk.so 也都存在同样的问题。

但在这个场景下，已经是最好的办法。



### 四、发起调用

可参考的代码如下：

```Java
package com.test2;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;

import java.io.File;
import java.nio.charset.StandardCharsets;

public class TEST2 extends AbstractJni {
    private final AndroidEmulator emulator;
    private final DvmClass NetCrypto;
    private final VM vm;

    public TEST2() {
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("cn.xiaochuankeji.tieba")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("D:\\Compilation_Enviroment\\unidbg-master\\unidbg-android\\src\\test\\java\\com\\test2\\right573.apk"));
        vm.setJni(this);
        vm.setVerbose(true);

        // 使用libandroid.so虚拟模块
        new AndroidModule(emulator, vm).register(memory);

        DalvikModule dm = vm.loadLibrary("net_crypto", true);
        NetCrypto = vm.resolveClass("com.izuiyou.network.NetCrypto");
        dm.callJNI_OnLoad(emulator);
    }

    public String callSign() {
        String arg1 = "hello world";
        byte[] arg2 = "V I 50".getBytes(StandardCharsets.UTF_8);
        String ret = NetCrypto.callStaticJniMethodObject(emulator, "sign(Ljava/lang/String;[B)Ljava/lang/String;", arg1, arg2).getValue().toString();
        return ret;
    }



    public static void main(String[] args) {
        TEST2 test = new TEST2();
        String result = test.callSign();
        System.out.println("call s result: " + result);
    }


}
```

因为是静态函数，而且返回值是字符串，所以采用**callStaticJniMethodObject**发起调用。

除此之外，参数1 和 2 是字符串和字节数组类型，都属于Unidbg会替我们处理类型转换的类型。



### 五、补JNI环境

本篇开始进入JNI补环境的处理逻辑，这里会留好几个坑，放到后文再讲，请读者稍安勿躁。

运行代码，报错如下：

```shell
JNIEnv->GetStringUtfChars("hello world") was called from RX@0x12066b07[libnet_crypto.so]0x66b07
JNIEnv->ReleaseStringUTFChars("hello world") was called from RX@0x12066b23[libnet_crypto.so]0x66b23
JNIEnv->FindClass(com/izuiyou/common/base/BaseApplication) was called from RX@0x1204da21[libnet_crypto.so]0x4da21
JNIEnv->GetStaticMethodID(com/izuiyou/common/base/BaseApplication.getAppContext()Landroid/content/Context;) => 0x2157b33c was called from RX@0x1204da57[libnet_crypto.so]0x4da57
[15:23:19 214]  WARN [com.github.unidbg.linux.ARM32SyscallHandler] (ARM32SyscallHandler:538) - handleInterrupt intno=2, NR=-452987556, svcNumber=0x170, PC=unidbg@0xfffe0794, LR=RX@0x1204db2f[libnet_crypto.so]0x4db2f, syscall=null
java.lang.UnsupportedOperationException: com/izuiyou/common/base/BaseApplication->getAppContext()Landroid/content/Context;
	at com.github.unidbg.linux.android.dvm.AbstractJni.callStaticObjectMethodV(AbstractJni.java:504)
	at com.github.unidbg.linux.android.dvm.AbstractJni.callStaticObjectMethodV(AbstractJni.java:438)
	at com.github.unidbg.linux.android.dvm.DvmMethod.callStaticObjectMethodV(DvmMethod.java:59)
	at com.github.unidbg.linux.android.dvm.DalvikVM$113.handle(DalvikVM.java:1815)
	at com.github.unidbg.linux.ARM32SyscallHandler.hook(ARM32SyscallHandler.java:131)
	at com.github.unidbg.arm.backend.Unicorn2Backend$11.hook(Unicorn2Backend.java:352)
	at com.github.unidbg.arm.backend.unicorn.Unicorn$NewHook.onInterrupt(Unicorn.java:109)
	at com.github.unidbg.arm.backend.unicorn.Unicorn.emu_start(Native Method)
	at com.github.unidbg.arm.backend.unicorn.Unicorn.emu_start(Unicorn.java:312)
	at com.github.unidbg.arm.backend.Unicorn2Backend.emu_start(Unicorn2Backend.java:389)
	at com.github.unidbg.AbstractEmulator.emulate(AbstractEmulator.java:378)
	at com.github.unidbg.thread.Function32.run(Function32.java:39)
	at com.github.unidbg.thread.MainTask.dispatch(MainTask.java:19)
	at com.github.unidbg.thread.UniThreadDispatcher.run(UniThreadDispatcher.java:165)
	at com.github.unidbg.thread.UniThreadDispatcher.runMainForResult(UniThreadDispatcher.java:97)
	at com.github.unidbg.AbstractEmulator.runMainForResult(AbstractEmulator.java:341)
	at com.github.unidbg.arm.AbstractARMEmulator.eFunc(AbstractARMEmulator.java:255)
	at com.github.unidbg.Module.emulateFunction(Module.java:163)
	at com.github.unidbg.linux.android.dvm.DvmObject.callJniMethod(DvmObject.java:135)
	at com.github.unidbg.linux.android.dvm.DvmClass.callStaticJniMethodObject(DvmClass.java:316)
	at com.test2.TEST2.callSign(TEST2.java:47)
	at com.test2.TEST2.main(TEST2.java:58)
```

首先，读者需要意识到，这并不是真正的“报错”，而是Unidbg为了提醒我们补JNI环境，主动抛出的异常。接下来首先讨论异常。



#### 5.1 异常

报错可以分为两部分

第一部分

```shell
[15:23:19 214]  WARN [com.github.unidbg.linux.ARM32SyscallHandler] (ARM32SyscallHandler:538) - handleInterrupt intno=2, NR=-452987556, svcNumber=0x170, PC=unidbg@0xfffe0794, LR=RX@0x1204db2f[libnet_crypto.so]0x4db2f, syscall=null
```

日志输出的位置是**[com.github.unidbg.linux.ARM32SyscallHandler] (ARM32SyscallHandler:538)**
![image-20250705152744055](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705152744055.png)

可能会感到疑惑，为什么处理JNI的逻辑，其报错在 **Arm32SyscallHandler**，这似乎是系统调用的处理模块吧？

事实上，Unidbg正是凭此实现了对JNI的代理，首先它构造了**JNIEnv**和**JavaVM**这两个JNI中的关键结构，它们是指向JNI函数表的二级指针。在处理函数表时，Unidbg将函数都导向一个八字节的跳板函数。

```c
svc #imm;
bx lr;
```

比如样本中so文件的**ReleaseStringUTFChars**函数
![image-20250705153939780](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705153939780.png)

汇编代码如下：

```c
.text:00066B14                 LDR             R0, [R6]
.text:00066B16                 LDR.W           R3, [R0,#0x2A8]
.text:00066B1A                 MOV             R0, R6
.text:00066B1C                 MOV             R1, R5
.text:00066B1E                 MOV             R2, R4
.text:00066B20                 BLX             R3
```

在真实的Android环境中，这里通过R3跳到了**ReleaseStringUTFChars**位于libart.so的真正实现上。

在Unidbg里，则是落到我们的跳板函数上。

对于此处的**ReleaseStringUTFChars**函数，是下面两条

```c
svc #0x1a1;
bx lr;
```

> **SVC**是软中断，Unicorn等CPU模拟器会拦截这些中断，进而Unidbg可以接管这些中断，并对JNI调用做模拟。可是Unidbg如何分辨系统调用和JNI调用？毕竟系统调用也是通过**SVC**软中断发起。这就依赖于**SVC**后面跟着的数字，这里我们称之为**imm**。

在系统调用的调用约定里，**imm**无实际意义，而且默认会使用0，即**SVC 0**，就像下面这样

```c
.text:0004147C                 MOV             R12, R7
.text:00041480                 LDR             R7, =0x142
.text:00041484                 SVC             0
```

因此，根据**imm**是否为0，Unidbg确认逻辑应该导向模拟的JNI函数还是模拟的系统调用。

换句话说，在Unidbg中，JNI函数被提升到了和系统调用相同的层级，因此JNI报错也发生在syscallHandler里面。

对于报错的这第一部分，有意义的事**LR**，它即JNI跳板函数的返回地址，对应于样本发起JNI调用的位置。

```shell
[15:23:19 214]  WARN [com.github.unidbg.linux.ARM32SyscallHandler] (ARM32SyscallHandler:538) - handleInterrupt intno=2, NR=-452987556, svcNumber=0x170, PC=unidbg@0xfffe0794, LR=RX@0x1204db2f[libnet_crypto.so]0x4db2f, syscall=null
```

第二部分是其余部分

```shell
java.lang.UnsupportedOperationException: com/izuiyou/common/base/BaseApplication->getAppContext()Landroid/content/Context;
	at com.github.unidbg.linux.android.dvm.AbstractJni.callStaticObjectMethodV(AbstractJni.java:504)
	at com.github.unidbg.linux.android.dvm.AbstractJni.callStaticObjectMethodV(AbstractJni.java:438)
	at com.github.unidbg.linux.android.dvm.DvmMethod.callStaticObjectMethodV(DvmMethod.java:59)
```

首先是Unidbg无法处理的函数其签名**com/izuiyou/common/base/BaseApplication->getAppContext()Landroid/content/Context;**，这个格式很清晰，即**com/izuiyou/common/base/BaseApplication**类的**getAppContext**方法。

再看它的调用栈，来自于**callStaticObjectMethodV**这个JNI方法。接下来讨论为什么要补JNI环境。



#### 5.2 补环境原因

为什么要补JNI环境？

上节讲到，Unidbg通过构造**JNIEnv**，**JavaVM**结构，辅之以**SVC**跳板函数，实现了对**JNI**的拦截和接管。

但到底如何去模拟JNI函数，这是问题的核心。Unidbg实现了一套JNI处理逻辑，当遇到JNI调用时，如果是**FindClass**、**NewGlobalRef**、**GetObjectClass**、**GetMethodID**、**GetStringLength**、**GetStringChars**、**ReleaseStringChars**等等函数，它都可以自洽处理，不需要使用者介入。

以GetStringLength为例，获取字符串长度，不需要使用者去做什么事。

```Java
Pointer _GetStringLength = svcMemory.registerSvc(new ArmSvc() {
    @Override
    public long handle(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        UnidbgPointer object = context.getPointerArg(1);
        DvmObject<?> string = getObject(object.toIntPeer());
        String value = (String) Objects.requireNonNull(string).getValue();
        return value.length();
    }
});
```

那么补JNI环境的需求在哪里？在于如果是**callStaticObjectMethod**、**callObjectMethod**、**getObjectField**、**getStaticIntField**等JNI函数，这些函数对样本的Java层数据做访问，Unidbg既未运行Dex，更没法运行Apk，因为需要借助使用者，去补充这些外部的信息。

因为担心用户意识不到补JNI的需求，所以通过抛出报错和打印堆栈予以提醒。

需要注意，并不是所有基于JNI发起的函数调用、字段访问都必须由用户处理，我们发现，其中有部分可以被预处理。举一些例子。

- Android PackageManager 类里的 GET_SIGNATURES 静态字段 ，它的值固定是 64
- String 类的 getBytes 方法
- List 实现类的 size 方法

为了减少用户的补JNI负担，所以Unidbg预处理了数百个常见的JNI函数调用和字段访问，逻辑位于**src/main/java/com/github/unidbg/linux/android/dvm/AbstractJni.java**类里。

比如**callBooleanMethodV**，调用和返回布尔值的实例方法，预处理了如下方法。

```Java
@Override
public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
    switch (signature) {
        case "java/util/Enumeration->hasMoreElements()Z":
            return ((Enumeration) dvmObject).hasMoreElements();
        case "java/util/ArrayList->isEmpty()Z":
            return ((ArrayListObject) dvmObject).isEmpty();
        case "java/util/Iterator->hasNext()Z":
            Object iterator = dvmObject.getValue();
            if (iterator instanceof Iterator) {
                return ((Iterator<?>) iterator).hasNext();
            }
        case "java/lang/String->startsWith(Ljava/lang/String;)Z":{
            String str = (String) dvmObject.getValue();
            StringObject prefix = vaList.getObjectArg(0);
            return str.startsWith(prefix.value);
        }
    }

    throw new UnsupportedOperationException(signature);
}
```

比如**getObjectField**，访问对象类型的实例字段，做了如下处理

```Java
@Override
public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
    if ("android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;".equals(signature) &&
            dvmObject instanceof PackageInfo) {
        PackageInfo packageInfo = (PackageInfo) dvmObject;
        if (packageInfo.getPackageName().equals(vm.getPackageName())) {
            CertificateMeta[] metas = vm.getSignatures();
            if (metas != null) {
                Signature[] signatures = new Signature[metas.length];
                for (int i = 0; i < metas.length; i++) {
                    signatures[i] = new Signature(vm, metas[i]);
                }
                return new ArrayObject(signatures);
            }
        }
    }
    if ("android/content/pm/PackageInfo->versionName:Ljava/lang/String;".equals(signature) &&
            dvmObject instanceof PackageInfo) {
        PackageInfo packageInfo = (PackageInfo) dvmObject;
        if (packageInfo.getPackageName().equals(vm.getPackageName())) {
            String versionName = vm.getVersionName();
            if (versionName != null) {
                return new StringObject(vm, versionName);
            }
        }
    }

    throw new UnsupportedOperationException(signature);
}
```

这两个调用是获取Apk签名信息以及版本信息，Unidbg之所以能处理，依赖我们传入的APK，解析出了这些信息。

在AbstractJNI 中，下面四类处理为主

- App 基本信息与签名
- JDK 加密解密与数字签名
- 字符串和容器类型
- Android FrameWork 类库

第一类就比如上面的两个，但不止于此，加载和解析APK让Unidbg获取了大量的信息。

比如处理获取包名：

```Java
@Override
public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
    if ("android/app/ActivityThread->currentPackageName()Ljava/lang/String;".equals(signature)) {
        String packageName = vm.getPackageName();
        if (packageName != null) {
            return new StringObject(vm, packageName);
        }
    }
    throw new UnsupportedOperationException(signature);
}
```

比如版本号：

```Java
@Override
public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
    if ("android/content/pm/PackageInfo->versionCode:I".equals(signature)) {
        return (int) vm.getVersionCode();
    }
    throw new UnsupportedOperationException(signature);
}
```

第二类是Java加解密和数字签名相关的方法，它主要服务于Apk签名校验，出现频率很高。

比如：

```Java
case "java/security/KeyFactory->getInstance(Ljava/lang/String;)Ljava/security/KeyFactory;":{
    StringObject algorithm = vaList.getObjectArg(0);
    assert algorithm != null;
    try {
        return dvmClass.newObject(KeyFactory.getInstance(algorithm.value));
    } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
    }
}
case "javax/crypto/Cipher->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;":{
    StringObject transformation = vaList.getObjectArg(0);
    assert transformation != null;
    try {
        return dvmClass.newObject(Cipher.getInstance(transformation.value));
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
        throw new IllegalStateException(e);
    }
}
case "java/security/MessageDigest->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;": {
    StringObject type = vaList.getObjectArg(0);
    assert type != null;
    try {
        return dvmClass.newObject(MessageDigest.getInstance(type.value));
    } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
    }
}
```

比如：

```Java
case "javax/crypto/spec/SecretKeySpec-><init>([BLjava/lang/String;)V":{
    byte[] key = (byte[]) vaList.getObjectArg(0).value;
    StringObject algorithm = vaList.getObjectArg(1);
    assert algorithm != null;
    SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithm.value);
    return dvmClass.newObject(secretKeySpec);
}
```

第三类是对基本类型的包装类、字符串、容器类型的处理。

比如：

```Java
@Override
public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
    switch (signature) {
        case "java/lang/String-><init>([B)V":
            ByteArray array = varArg.getObjectArg(0);
            return new StringObject(vm, new String(array.getValue()));
        case "java/lang/String-><init>([BLjava/lang/String;)V":
            array = varArg.getObjectArg(0);
            StringObject string = varArg.getObjectArg(1);
            try {
                return new StringObject(vm, new String(array.getValue(), string.getValue()));
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException(e);
            }
    }

    throw new UnsupportedOperationException(signature);
}
```

再比如：

```Java
@Override
public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
    switch (signature) {
        case "java/util/Enumeration->hasMoreElements()Z":
            return ((Enumeration) dvmObject).hasMoreElements();
        case "java/util/ArrayList->isEmpty()Z":
            return ((ArrayListObject) dvmObject).isEmpty();
        case "java/util/Iterator->hasNext()Z":
            Object iterator = dvmObject.getValue();
            if (iterator instanceof Iterator) {
                return ((Iterator<?>) iterator).hasNext();
            }
        case "java/lang/String->startsWith(Ljava/lang/String;)Z":{
            String str = (String) dvmObject.getValue();
            StringObject prefix = vaList.getObjectArg(0);
            return str.startsWith(prefix.value);
        }
    }

    throw new UnsupportedOperationException(signature);
}
```

再比如：

```Java
case "java/lang/Integer->intValue()I": {
    DvmInteger integer = (DvmInteger) dvmObject;
    return integer.value;
}
case "java/util/List->size()I":
    List<?> list = (List<?>) dvmObject.getValue();
    return list.size();
case "java/util/Map->size()I":
    Map<?, ?> map = (Map<?, ?>) dvmObject.getValue();
    return map.size();
```

比如：

```Java
case "java/util/ArrayList->remove(I)Ljava/lang/Object;": {
    int index = vaList.getIntArg(0);
    ArrayListObject list = (ArrayListObject) dvmObject;
    return list.value.remove(index);
}
case "java/util/List->get(I)Ljava/lang/Object;":
    List<?> list = (List<?>) dvmObject.getValue();
    return (DvmObject<?>) list.get(vaList.getIntArg(0));
case "java/util/Map->entrySet()Ljava/util/Set;":
    Map<?, ?> map = (Map<?, ?>) dvmObject.getValue();
    return vm.resolveClass("java/util/Set").newObject(map.entrySet());
case "java/util/Set->iterator()Ljava/util/Iterator;":
    Set<?> set = (Set<?>) dvmObject.getValue();
    return vm.resolveClass("java/util/Iterator").newObject(set.iterator());
```

比如：

```Java
case "java/lang/String->getBytes()[B": {
    String str = (String) dvmObject.getValue();
    return new ByteArray(vm, str.getBytes());
}
case "java/lang/String->getBytes(Ljava/lang/String;)[B":
    String str = (String) dvmObject.getValue();
    StringObject charsetName = vaList.getObjectArg(0);
    assert charsetName != null;
    try {
        return new ByteArray(vm, str.getBytes(charsetName.value));
    } catch (UnsupportedEncodingException e) {
        throw new IllegalStateException(e);
    }
```

第四类是依赖于Android FrameWork的类库，它们没法在普通的Java环境里良好的处理，因此需要做一些粗糙的模拟或者占位。

比如Android系统服务

```Java
case "android/app/Application->getSystemService(Ljava/lang/String;)Ljava/lang/Object;": {
    StringObject serviceName = vaList.getObjectArg(0);
    assert serviceName != null;
    return new SystemService(vm, serviceName.getValue());
```

SystemService 的实现如下，就是大量的简单占位，调用其中的方法实际获取数据时，还是要使用者来补。

```Java
package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class SystemService extends DvmObject<String> {

    public static final String WIFI_SERVICE = "wifi";
    public static final String CONNECTIVITY_SERVICE = "connectivity";
    public static final String TELEPHONY_SERVICE = "phone";
    public static final String ACCESSIBILITY_SERVICE = "accessibility";
    public static final String KEYGUARD_SERVICE = "keyguard";
    public static final String ACTIVITY_SERVICE = "activity";
    public static final String SENSOR_SERVICE = "sensor";
    public static final String INPUT_METHOD_SERVICE = "input_method";
    public static final String LOCATION_SERVICE = "location";
    public static final String WINDOW_SERVICE = "window";
    public static final String UI_MODE_SERVICE = "uimode";
    public static final String DISPLAY_SERVICE = "display";
    public static final String AUDIO_SERVICE = "audio";
    
    public SystemService(VM vm, String serviceName) {
        super(getObjectType(vm, serviceName), serviceName);
    }

    private static DvmClass getObjectType(VM vm, String serviceName) {
        switch (serviceName) {
            case TELEPHONY_SERVICE:
                return vm.resolveClass("android/telephony/TelephonyManager");
            case WIFI_SERVICE:
                return vm.resolveClass("android/net/wifi/WifiManager");
            case CONNECTIVITY_SERVICE:
                return vm.resolveClass("android/net/ConnectivityManager");
            case ACCESSIBILITY_SERVICE:
                return vm.resolveClass("android/view/accessibility/AccessibilityManager");
            case KEYGUARD_SERVICE:
                return vm.resolveClass("android/app/KeyguardManager");
            case ACTIVITY_SERVICE:
                return vm.resolveClass("android/os/BinderProxy"); // android/app/ActivityManager
            case SENSOR_SERVICE:
                return vm.resolveClass("android/hardware/SensorManager");
            case INPUT_METHOD_SERVICE:
                return vm.resolveClass("android/view/inputmethod/InputMethodManager");
            case LOCATION_SERVICE:
                return vm.resolveClass("android/location/LocationManager");
            case WINDOW_SERVICE:
                return vm.resolveClass("android/view/WindowManager");
            case UI_MODE_SERVICE:
                return vm.resolveClass("android/app/UiModeManager");
            case DISPLAY_SERVICE:
                return vm.resolveClass("android/hardware/display/DisplayManager");
            case AUDIO_SERVICE:
                return vm.resolveClass("android/media/AudioManager");
            default:
                throw new BackendException("service failed: " + serviceName);
        }
    }

}
```

在过去几年的更新里，Unidbg 一直在对 AbstractJNI 做扩充，让它预处理更多的逻辑，减少用户的使用负担。

关于 AbstractJNI 可以做两点总结。

1. 确实能让我们免于一些补环境的苦恼
2. 相较于所有可能的 JNI 访问，它只是杯水车薪，补 JNI 环境这个步骤不可避免。

我们先看第一点，前两篇样本的处理，都没有遇到 JNI 补环境的需求，这就是 AbstractJNI 替我们代劳了。

比如第一篇文章的日志如下：

```shell
JNIEnv->FindClass(android/app/ActivityThread) was called from RX@0x12010e20[liboasiscore.so]0x10e20
JNIEnv->GetStaticMethodID(android/app/ActivityThread.currentApplication()Landroid/app/Application;) => 0xc1600375 was called from RX@0x12010f40[liboasiscore.so]0x10f40
JNIEnv->CallStaticObjectMethodV(class android/app/ActivityThread, currentApplication() => android.app.Application@3d680b5a) was called from RX@0x120126cc[liboasiscore.so]0x126cc
JNIEnv->FindClass(android/content/ContextWrapper) was called from RX@0x12011024[liboasiscore.so]0x11024
JNIEnv->GetMethodID(android/content/ContextWrapper.getPackageManager()Landroid/content/pm/PackageManager;) => 0x53f2c391 was called from RX@0x12011050[liboasiscore.so]0x11050
JNIEnv->CallObjectMethodV(android.app.Application@3d680b5a, getPackageManager() => android.content.pm.PackageManager@4b5d6a01) was called from RX@0x12012630[liboasiscore.so]0x12630
JNIEnv->GetMethodID(android/content/ContextWrapper.getPackageName()Ljava/lang/String;) => 0x8bcc2d71 was called from RX@0x120110bc[liboasiscore.so]0x110bc
JNIEnv->CallObjectMethodV(android.app.Application@3d680b5a, getPackageName() => "com.sina.oasis") was called from RX@0x12012630[liboasiscore.so]0x12630
JNIEnv->GetStringUtfChars("com.sina.oasis") was called from RX@0x12011108[liboasiscore.so]0x11108
JNIEnv->GetMethodID(android/content/pm/PackageManager.getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;) => 0x3bca8377 was called from RX@0x12011168[liboasiscore.so]0x11168
JNIEnv->CallObjectMethodV(android.content.pm.PackageManager@4b5d6a01, getPackageInfo("com.sina.oasis", 0x40) => android.content.pm.PackageInfo@3e2e18f2) was called from RX@0x12012630[liboasiscore.so]0x12630
JNIEnv->GetFieldID(android/content/pm/PackageInfo.signatures [Landroid/content/pm/Signature;) => 0x25f17218 was called from RX@0x120111bc[liboasiscore.so]0x111bc
JNIEnv->GetObjectField(android.content.pm.PackageInfo@3e2e18f2, signatures [Landroid/content/pm/Signature; => [android.content.pm.Signature@8f4ea7c]) was called from RX@0x120111d4[liboasiscore.so]0x111d4
JNIEnv->GetObjectArrayElement([android.content.pm.Signature@8f4ea7c], 0) => android.content.pm.Signature@8f4ea7c was called from RX@0x120111ec[liboasiscore.so]0x111ec
JNIEnv->GetMethodID(android/content/pm/Signature.toCharsString()Ljava/lang/String;) => 0x7a908191 was called from RX@0x1201122c[liboasiscore.so]0x1122c
JNIEnv->CallObjectMethodV(android.content.pm.Signature@8f4ea7c, toCharsString() => "30820295308201fea00302010202044b4ef1bf300d06092a864886f70d010105050030818d310b300906035504061302434e3110300e060355040813074265694a696e673110300e060355040713074265694a696e67312c302a060355040a132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c7464312c302a060355040b132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c74643020170d3130303131343130323831355a180f32303630303130323130323831355a30818d310b300906035504061302434e3110300e060355040813074265694a696e673110300e060355040713074265694a696e67312c302a060355040a132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c7464312c302a060355040b132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c746430819f300d06092a864886f70d010101050003818d00308189028181009d367115bc206c86c237bb56c8e9033111889b5691f051b28d1aa8e42b66b7413657635b44786ea7e85d451a12a82a331fced99c48717922170b7fc9bc1040753c0d38b4cf2b22094b1df7c55705b0989441e75913a1a8bd2bc591aa729a1013c277c01c98cbec7da5ad7778b2fad62b85ac29ca28ced588638c98d6b7df5a130203010001300d06092a864886f70d0101050500038181000ad4b4c4dec800bd8fd2991adfd70676fce8ba9692ae50475f60ec468d1b758a665e961a3aedbece9fd4d7ce9295cd83f5f19dc441a065689d9820faedbb7c4a4c4635f5ba1293f6da4b72ed32fb8795f736a20c95cda776402099054fccefb4a1a558664ab8d637288feceba9508aa907fc1fe2b1ae5a0dec954ed831c0bea4") was called from RX@0x12012630[liboasiscore.so]0x12630
JNIEnv->GetStringUtfChars("30820295308201fea00302010202044b4ef1bf300d06092a864886f70d010105050030818d310b300906035504061302434e3110300e060355040813074265694a696e673110300e060355040713074265694a696e67312c302a060355040a132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c7464312c302a060355040b132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c74643020170d3130303131343130323831355a180f32303630303130323130323831355a30818d310b300906035504061302434e3110300e060355040813074265694a696e673110300e060355040713074265694a696e67312c302a060355040a132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c7464312c302a060355040b132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c746430819f300d06092a864886f70d010101050003818d00308189028181009d367115bc206c86c237bb56c8e9033111889b5691f051b28d1aa8e42b66b7413657635b44786ea7e85d451a12a82a331fced99c48717922170b7fc9bc1040753c0d38b4cf2b22094b1df7c55705b0989441e75913a1a8bd2bc591aa729a1013c277c01c98cbec7da5ad7778b2fad62b85ac29ca28ced588638c98d6b7df5a130203010001300d06092a864886f70d0101050500038181000ad4b4c4dec800bd8fd2991adfd70676fce8ba9692ae50475f60ec468d1b758a665e961a3aedbece9fd4d7ce9295cd83f5f19dc441a065689d9820faedbb7c4a4c4635f5ba1293f6da4b72ed32fb8795f736a20c95cda776402099054fccefb4a1a558664ab8d637288feceba9508aa907fc1fe2b1ae5a0dec954ed831c0bea4") was called from RX@0x12011278[liboasiscore.so]0x11278
JNIEnv->ReleaseStringUTFChars("30820295308201fea00302010202044b4ef1bf300d06092a864886f70d010105050030818d310b300906035504061302434e3110300e060355040813074265694a696e673110300e060355040713074265694a696e67312c302a060355040a132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c7464312c302a060355040b132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c74643020170d3130303131343130323831355a180f32303630303130323130323831355a30818d310b300906035504061302434e3110300e060355040813074265694a696e673110300e060355040713074265694a696e67312c302a060355040a132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c7464312c302a060355040b132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c746430819f300d06092a864886f70d010101050003818d00308189028181009d367115bc206c86c237bb56c8e9033111889b5691f051b28d1aa8e42b66b7413657635b44786ea7e85d451a12a82a331fced99c48717922170b7fc9bc1040753c0d38b4cf2b22094b1df7c55705b0989441e75913a1a8bd2bc591aa729a1013c277c01c98cbec7da5ad7778b2fad62b85ac29ca28ced588638c98d6b7df5a130203010001300d06092a864886f70d0101050500038181000ad4b4c4dec800bd8fd2991adfd70676fce8ba9692ae50475f60ec468d1b758a665e961a3aedbece9fd4d7ce9295cd83f5f19dc441a065689d9820faedbb7c4a4c4635f5ba1293f6da4b72ed32fb8795f736a20c95cda776402099054fccefb4a1a558664ab8d637288feceba9508aa907fc1fe2b1ae5a0dec954ed831c0bea4") was called from RX@0x120112b0[liboasiscore.so]0x112b0
JNIEnv->FindClass(com/weibo/xvideo/NativeApi) was called from RX@0x12011348[liboasiscore.so]0x11348
JNIEnv->RegisterNatives(com/weibo/xvideo/NativeApi, RW@0x1205d100[liboasiscore.so]0x5d100, 4) was called from RX@0x120113e0[liboasiscore.so]0x113e0
RegisterNative(com/weibo/xvideo/NativeApi, s([BZ)Ljava/lang/String;, RX@0x120116cc[liboasiscore.so]0x116cc)
RegisterNative(com/weibo/xvideo/NativeApi, e(Ljava/lang/String;)Ljava/lang/String;, RX@0x12011af4[liboasiscore.so]0x11af4)
RegisterNative(com/weibo/xvideo/NativeApi, d(Ljava/lang/String;)Ljava/lang/String;, RX@0x12011cd8[liboasiscore.so]0x11cd8)
RegisterNative(com/weibo/xvideo/NativeApi, dg(Ljava/lang/String;Z)Ljava/lang/String;, RX@0x1201220c[liboasiscore.so]0x1220c)
Find native function Java_com_weibo_xvideo_NativeApi_s => RX@0x120116cc[liboasiscore.so]0x116cc
JNIEnv->GetByteArrayElements(false) => [B@5b8dfcc1 was called from RX@0x12011734[liboasiscore.so]0x11734
JNIEnv->GetArrayLength([B@5b8dfcc1 => 272) was called from RX@0x1201174c[liboasiscore.so]0x1174c
JNIEnv->NewStringUTF("1e3780f50056a3fea76b35592bfc3efc") was called from RX@0x1201191c[liboasiscore.so]0x1191c
Call s result:
1e3780f50056a3fea76b35592bfc3efc
```

其中的`FindClass`、`GetStaticMethodID`、`GetMethodID`、`GetStringUtfChars`、`GetFieldID`、`GetObjectArrayElement`、`ReleaseStringUTFChars`、`RegisterNatives`、`GetArrayLength`、`NewStringUTF`是 Unidbg 直接可以处理的内容。

其中的`CallStaticObjectMethodV`、`CallObjectMethodV`、`GetObjectField`则由 AbstrctJNI 处理，比如下面这条

```shell
JNIEnv->CallStaticObjectMethodV(class android/app/ActivityThread, currentApplication() => android.app.Application@3d680b5a) was called from RX@0x120126cc[liboasiscore.so]0x126cc
```

而第二篇样本日志输出如下：

```shell
Find native function Java_com_sina_weibo_security_WeiboSecurityUtils_calculateS => RX@0x12001e7d[libutility.so]0x1e7d
JNIEnv->FindClass(android/content/ContextWrapper) was called from RX@0x12002c4f[libutility.so]0x2c4f
JNIEnv->GetMethodID(android/content/ContextWrapper.getPackageManager()Landroid/content/pm/PackageManager;) => 0x53f2c391 was called from RX@0x12002c69[libutility.so]0x2c69
JNIEnv->FindClass(android/content/pm/PackageManager) was called from RX@0x12002c79[libutility.so]0x2c79
JNIEnv->CallObjectMethod(android.app.Application@60704c, getPackageManager() => android.content.pm.PackageManager@2805c96b) was called from RX@0x12002c8d[libutility.so]0x2c8d
JNIEnv->FindClass(android/content/pm/PackageInfo) was called from RX@0x12002c9d[libutility.so]0x2c9d
JNIEnv->GetMethodID(android/content/pm/PackageManager.getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;) => 0x3bca8377 was called from RX@0x12002cb5[libutility.so]0x2cb5
JNIEnv->NewStringUTF("com.weico.international") was called from RX@0x12002cd1[libutility.so]0x2cd1
JNIEnv->CallObjectMethod(android.content.pm.PackageManager@2805c96b, getPackageInfo("com.weico.international", 0x40) => android.content.pm.PackageInfo@5db250b4) was called from RX@0x12002ce1[libutility.so]0x2ce1
JNIEnv->GetFieldID(android/content/pm/PackageInfo.signatures [Landroid/content/pm/Signature;) => 0x25f17218 was called from RX@0x12002d13[libutility.so]0x2d13
JNIEnv->GetObjectField(android.content.pm.PackageInfo@5db250b4, signatures [Landroid/content/pm/Signature; => [android.content.pm.Signature@50b472aa]) was called from RX@0x12002d25[libutility.so]0x2d25
JNIEnv->FindClass(android/content/pm/Signature) was called from RX@0x12002d35[libutility.so]0x2d35
JNIEnv->GetMethodID(android/content/pm/Signature.toByteArray()[B) => 0x6a3e2031 was called from RX@0x12002d4d[libutility.so]0x2d4d
JNIEnv->GetObjectArrayElement([android.content.pm.Signature@50b472aa], 0) => android.content.pm.Signature@50b472aa was called from RX@0x12002d61[libutility.so]0x2d61
JNIEnv->CallObjectMethod(android.content.pm.Signature@50b472aa, toByteArray() => [B@4ac3c60d) was called from RX@0x12002d71[libutility.so]0x2d71
WInlineHookFunction free = RW@0x12176000
JNIEnv->GetStringUtfChars("CypCHG2kSlRkdvr2RG1QF8b2lCWXl7k7") was called from RX@0x12001eb3[libutility.so]0x1eb3
JNIEnv->GetStringUtfChars("7926844437") was called from RX@0x12001ec1[libutility.so]0x1ec1
JNIEnv->FindClass(java/lang/String) was called from RX@0x12001f33[libutility.so]0x1f33
JNIEnv->GetMethodID(java/lang/String.<init>([BLjava/lang/String;)V) => 0x782c535e was called from RX@0x12001f4b[libutility.so]0x1f4b
JNIEnv->NewByteArray(8) was called from RX@0x12001f61[libutility.so]0x1f61
JNIEnv->SetByteArrayRegion([B@0x0000000000000000, 0, 8, RW@0x121d3010) was called from RX@0x12001f7f[libutility.so]0x1f7f
JNIEnv->NewStringUTF("utf-8") was called from RX@0x12001f8f[libutility.so]0x1f8f
JNIEnv->NewObject(class java/lang/String, <init>([B@0x3164356134306466, "utf-8") => "1d5a40df") was called from RX@0x12001f9f[libutility.so]0x1f9f
WInlineHookFunction free = RW@0x121d3010
WInlineHookFunction free = RW@0x121d4000
JNIEnv->ReleaseStringUTFChars("7926844437") was called from RX@0x12001fbd[libutility.so]0x1fbd
call s result:1d5a40df
```

样本通过 JNI 调用了获取签名的相关 JAVA 方法，AbstractJNI 替我们做了处理。



#### 5.3 基本规范

回到最初的报错上

```shell
JNIEnv->GetStringUtfChars("hello world") was called from RX@0x12066b07[libnet_crypto.so]0x66b07
JNIEnv->ReleaseStringUTFChars("hello world") was called from RX@0x12066b23[libnet_crypto.so]0x66b23
JNIEnv->FindClass(com/izuiyou/common/base/BaseApplication) was called from RX@0x1204da21[libnet_crypto.so]0x4da21
JNIEnv->GetStaticMethodID(com/izuiyou/common/base/BaseApplication.getAppContext()Landroid/content/Context;) => 0x2157b33c was called from RX@0x1204da57[libnet_crypto.so]0x4da57
[15:23:19 214]  WARN [com.github.unidbg.linux.ARM32SyscallHandler] (ARM32SyscallHandler:538) - handleInterrupt intno=2, NR=-452987556, svcNumber=0x170, PC=unidbg@0xfffe0794, LR=RX@0x1204db2f[libnet_crypto.so]0x4db2f, syscall=null
java.lang.UnsupportedOperationException: com/izuiyou/common/base/BaseApplication->getAppContext()Landroid/content/Context;
	at com.github.unidbg.linux.android.dvm.AbstractJni.callStaticObjectMethodV(AbstractJni.java:504)
	at com.github.unidbg.linux.android.dvm.AbstractJni.callStaticObjectMethodV(AbstractJni.java:438)
	at com.github.unidbg.linux.android.dvm.DvmMethod.callStaticObjectMethodV(DvmMethod.java:59)
	at com.github.unidbg.linux.android.dvm.DalvikVM$113.handle(DalvikVM.java:1815)
	at com.github.unidbg.linux.ARM32SyscallHandler.hook(ARM32SyscallHandler.java:131)
	at com.github.unidbg.arm.backend.Unicorn2Backend$11.hook(Unicorn2Backend.java:352)
	at com.github.unidbg.arm.backend.unicorn.Unicorn$NewHook.onInterrupt(Unicorn.java:109)
	at com.github.unidbg.arm.backend.unicorn.Unicorn.emu_start(Native Method)
	at com.github.unidbg.arm.backend.unicorn.Unicorn.emu_start(Unicorn.java:312)
	at com.github.unidbg.arm.backend.Unicorn2Backend.emu_start(Unicorn2Backend.java:389)
	at com.github.unidbg.AbstractEmulator.emulate(AbstractEmulator.java:378)
	at com.github.unidbg.thread.Function32.run(Function32.java:39)
	at com.github.unidbg.thread.MainTask.dispatch(MainTask.java:19)
	at com.github.unidbg.thread.UniThreadDispatcher.run(UniThreadDispatcher.java:165)
	at com.github.unidbg.thread.UniThreadDispatcher.runMainForResult(UniThreadDispatcher.java:97)
	at com.github.unidbg.AbstractEmulator.runMainForResult(AbstractEmulator.java:341)
	at com.github.unidbg.arm.AbstractARMEmulator.eFunc(AbstractARMEmulator.java:255)
	at com.github.unidbg.Module.emulateFunction(Module.java:163)
	at com.github.unidbg.linux.android.dvm.DvmObject.callJniMethod(DvmObject.java:135)
	at com.github.unidbg.linux.android.dvm.DvmClass.callStaticJniMethodObject(DvmClass.java:316)
	at com.test2.TEST2.callSign(TEST2.java:47)
	at com.test2.TEST2.main(TEST2.java:58)
```

函数签名是`com/izuiyou/common/base/BaseApplication->getAppContext()Landroid/content/Context;`根据抛出的异常，它来自`callStaticObjectMethodV`调用。

如何构造和补 Context 是一个特殊问题，下面这个构造方式在绝大多数情况下可行。

```Java
DvmObject<?> context = vm.resolveClass("android/app/Application", vm.resolveClass("android/content/ContextWrapper", vm.resolveClass("android/content/Context"))).newObject(null);
```

但这里我们使用另一个方式构造，为什么要这么做，这是一个小坑，放后文讨论，请读者先忍耐一下。

```Java
DvmObject<?> context = vm.resolveClass("cn/xiaochuankeji/tieba/AppController").newObject(null);
```

接下来补环境，我们可以在 AbstractJNI 的 callStaticObjectMethodV 里添加对这个方法的处理，如下所示。

![img](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1667975125845-da7b2d2b-94a4-4cd5-b8de-a900955e2ec4.png)

但这么做不是好办法，如果想将自己写的 Unidbg 代码分享给他人，或迁移到其他设备上，就必须要把 AbstractJNI 一并转移，这有些麻烦。除此之外，我们补的也不一定特别好，放到 AbstractJNI 里会“污染”环境。更惯常的做法是让本类继承 AbstractJNI，在创建虚拟机时`vm.setJni`设置为当前类。

```Java
public TEST2() {
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("cn.xiaochuankeji.tieba")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("unidbg-android\\src\\test\\java\\com\\test2\\right573.apk"));

        //设置 JNI
        vm.setJni(this);
        vm.setVerbose(true);

        // 使用libandroid.so虚拟模块
        new AndroidModule(emulator, vm).register(memory);

        DalvikModule dm = vm.loadLibrary("net_crypto", true);
        NetCrypto = vm.resolveClass("com.izuiyou.network.NetCrypto");
        dm.callJNI_OnLoad(emulator);
    }
```

然后本类里重写 callStaticObjectMethodV 方法，处理目标方法。

```Java
@Override
public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
    switch (signature){
        case "com/izuiyou/common/base/BaseApplication->getAppContext()Landroid/content/Context;":{
            DvmObject<?> context = vm.resolveClass("cn/xiaochuankeji/tieba/AppController").newObject(null);
            return context;
        }
    }
    return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
}
```

这里要警惕张冠李戴，callStaticObjectMethodV 和 callStaticObjectMethod 是两个不同的 JNI 方法，不要混淆，更不要补错地方哭错坟。

在有些情况下，样本过于复杂，要处理的 JNI 调用太多，也可以创建一个单独的 JNI 处理类。

```Java
package com.izuiyou;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.dvm.*;

public class zuiYouJNI extends AbstractJni {
    private final AndroidEmulator emulator;

    public zuiYouJNI(AndroidEmulator emulator){
        this.emulator = emulator;
    }
    
}
```

在本类 setJNI 也对应改变。

```Java
vm.setJni(new zuiYouJNI(emulator));
```



#### 5.4 开始补环境

言归正传，处理完这个JNI调用

```Java
package com.test2;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;

import java.io.File;
import java.nio.charset.StandardCharsets;

public class TEST2 extends AbstractJni {
    private final AndroidEmulator emulator;
    private final DvmClass NetCrypto;
    private final VM vm;

    public TEST2() {
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("cn.xiaochuankeji.tieba")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("unidbg-android\\src\\test\\java\\com\\test2\\right573.apk"));

        //设置 JNI
        vm.setJni(this);
        vm.setVerbose(true);

        // 使用libandroid.so虚拟模块
        new AndroidModule(emulator, vm).register(memory);

        DalvikModule dm = vm.loadLibrary("net_crypto", true);
        NetCrypto = vm.resolveClass("com.izuiyou.network.NetCrypto");
        dm.callJNI_OnLoad(emulator);
    }

    public String callSign() {
        String arg1 = "hello world";
        byte[] arg2 = "V I 50".getBytes(StandardCharsets.UTF_8);
        String ret = null;
        try {
            ret = NetCrypto.callStaticJniMethodObject(emulator, "sign(Ljava/lang/String;[B)Ljava/lang/String;", arg1, arg2).getValue().toString();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/izuiyou/common/base/BaseApplication->getAppContext()Landroid/content/Context;": {
                DvmObject<?> context = vm.resolveClass("cn/xiaochuankeji/tieba/AppController").newObject(null);
                return context;
            }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }


    public static void main(String[] args) {
        TEST2 test = new TEST2();
        String result = test.callSign();
        System.out.println("call s result: " + result);
    }
}
```

继续运行，遇到了新的JNI 补环境。
![image-20250705164702773](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705164702773.png)

获取包管理器如何返回？AbstractJNI 里有可供参考的代码。
![image-20250705165040195](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705165040195.png)

重写，参考AbstractJNI 去补 PackageManager。

```java
@Override
public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
    switch (signature){
        case "cn/xiaochuankeji/tieba/AppController->getPackageManager()Landroid/content/pm/PackageManager;":{
            return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
        }
    }
    return super.callObjectMethodV(vm, dvmObject, signature, vaList);
```

继续运行
![image-20250705165424673](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705165424673.png)

获取包名，AbstractJNI 里同样有这个处理逻辑。
![image-20250705165455598](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705165455598.png)

照抄一下

```Java
@Override
public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
    switch (signature){
        case "cn/xiaochuankeji/tieba/AppController->getPackageManager()Landroid/content/pm/PackageManager;":{
            return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
        }
        case "cn/xiaochuankeji/tieba/AppController->getPackageName()Ljava/lang/String;":{
            String packageName = vm.getPackageName();
            if (packageName != null) {
                return new StringObject(vm, packageName);
            }
            break;
        }
    }
    return super.callObjectMethodV(vm, dvmObject, signature, vaList);
}
```

继续运行

![image-20250705165811357](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705165811357.png)

在 AbstractJNI 里找 getClass 的处理逻辑。
![image-20250705165854570](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705165854570.png)

照抄

```Java
case "cn/xiaochuankeji/tieba/AppController->getClass()Ljava/lang/Class;":{
    return dvmObject.getObjectType();
}
```

继续运行
![image-20250705170044840](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705170044840.png)

这在 AbstractJNI 里可没有，像下面这样处理，为什么这么做同样放到后面讨论。

```Java
case "java/lang/Class->getSimpleName()Ljava/lang/String;":{
    String className = ((DvmClass) dvmObject).getClassName();
    String[] name = className.split("/");
    return new StringObject(vm, name[name.length - 1]);
}
```

继续运行
![image-20250705170221889](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705170221889.png)

Context 的 getFilesDir 返回什么？像下面这样处理，为什么这么做放到后面讨论。

```Java
case "cn/xiaochuankeji/tieba/AppController->getFilesDir()Ljava/io/File;":{
    return vm.resolveClass("java/io/File").newObject(null);
}
```

运行发现新报错
![image-20250705170311740](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705170311740.png)

像下面这样补，为什么这么做放到后面讨论。

```Java
case "cn/xiaochuankeji/tieba/AppController->getFilesDir()Ljava/io/File;":{
    return vm.resolveClass("java/io/File").newObject("/data/data/cn.xiaochuankeji.tieba/files");
}
case "java/io/File->getAbsolutePath()Ljava/lang/String;":{
    return new StringObject(vm, dvmObject.getValue().toString());
}
```

继续运行，走到了检测 debug 相关的逻辑
![image-20250705170553628](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705170553628.png)

返回false

```Java
@Override
public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
    switch (signature){
        case "android/os/Debug->isDebuggerConnected()Z":{
            return false;
        }
    }
    return super.callStaticBooleanMethodV(vm, dvmClass, signature, vaList);
}
```

继续运行，获取进程ID
![image-20250705170703469](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705170703469.png)

返回Unidbg所生成的PID

```Java
@Override
public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
    switch (signature){
        case "android/os/Process->myPid()I":{
            return emulator.getPid();
        }
    }
    return super.callStaticIntMethodV(vm, dvmClass, signature, vaList);
}
```

这里我们讨论一下pid的问题，不同的项目在此有不同的模拟思路。

比如qiling采用硬编码，返回0x512，即Unidbg环境里，进程的ID总是0x512.

```python
def ql_syscall_getpid(ql: Qiling):
    return 0x512
```

ExAndroidNativeEmu 返回项目自身的 pid

```python
def get_pid(self):
    return os.getpid()
```

Unidbg 同理，但它处理的更精细

```Java
// 获取当前JVM进程的PID
String name = ManagementFactory.getRuntimeMXBean().getName();
String pid = name.split("@")[0];
// 解析为数字，取低 15 位
this.pid = Integer.parseInt(pid) & 0x7fff;
```

它将获取到的进程 ID 和 0x7FFF 做与运算，按照与运算的规则，这舍去了高位，只保留较低的 15 比特。

原因在于，Linux 以及基于它的 Android 系统上，默认 PID 最大就是 0x8000（32768）。

```
#define PID_MAX 0x8000
```

可以在 adb shell 中验证这一点

```
blueline:/ $ cat /proc/sys/kernel/pid_max
32768
blueline:/ $
```

MacOS 上进程 ID 可达 100000，Windows 上更是不做限制。

这意味着，如果 Unidbg 的运行环境并非 Linux，而是 MacOS 或 Windows，那么获取到的 Pid 可能超出 Android 环境所限制的最大进程号。、

因此出于规范角度，Unidbg 抹去了当前 Pid 的高位，确保其小于`PID_MAX`。

在 Unidbg 里 PID 是私有的`final`变量，如果你想修改 PID，需要修改位于`unidbg-api/src/main/java/com/github/unidbg/AbstractEmulator.java` 的源码，这其实不是很方便，固定 pid 的需求其实也很多，如果 Unidbg 提供一个`setPid`的方法会很好.

运行测试，得到结果，符合我们的预期。

![image-20250705171217271](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250705171217271.png)

```shell
call s result:v2-b94195d5f3c2ad3a876f13346fa283a0
```



### 六、尾声

读者可能有很多困惑，在补环境的处理中留了不少坑，这应该也让大家意识到，补 JNI 环境是一个硬骨头，需要学习一番才能搞定。从下一篇开始，我们正式讨论如何补 JNI 环境。



### 七、参考

[Unidbg 的基本使用（三）](https://www.yuque.com/lilac-2hqvv/xdwlsg/bmf8lm68ffvhrfu0?#uMicr)
