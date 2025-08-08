---
title: 从实践中学习unidbg使用(二)
tags: [Unidbg]
categories: Unidbg学习
---

# 从实践中学习unidbg使用(二)

### 一、引言

本篇中的APK详见参考文章

目标APK: sinaInternational.apk

目标方法实现：libutility.so



### 二、任务描述

apk放到JADX中进行反编译，并找到**com.sina.weibo.security**类。目标函数是其中的calculateS函数

```Java
package com.sina.weibo.security;

import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import com.taobao.accs.utl.UtilityImpl;
import com.umeng.message.MsgConstant;
import com.weico.international.WApplication;
import permissions.dispatcher.PermissionUtils;

/* loaded from: classes.dex */
public class WeiboSecurityUtils {
    public static WeiboSecurityUtils instance;
    private static Object mCalculateSLock;
    private static String sIValue;
    private static String sImei;
    private static String sMac;
    private static String sSeed;
    private static String sValue;

    public native String calculateS(Context context, String str, String str2);

    public native String getIValue(Context context, String str);

    static {
        System.loadLibrary("utility");
        instance = null;
        sImei = "";
        sMac = "";
        mCalculateSLock = new Object();
    }

    private WeiboSecurityUtils() {
    }

    public static synchronized WeiboSecurityUtils getInstance() {
        WeiboSecurityUtils weiboSecurityUtils;
        synchronized (WeiboSecurityUtils.class) {
            if (instance == null) {
                instance = new WeiboSecurityUtils();
            }
            weiboSecurityUtils = instance;
        }
        return weiboSecurityUtils;
    }

    public static String calculateSInJava(Context context, String srcArray, String pin) {
        String str;
        synchronized (mCalculateSLock) {
            if (srcArray.equals(sSeed) && !TextUtils.isEmpty(sValue)) {
                str = sValue;
            } else if (context != null) {
                sSeed = srcArray;
                sValue = getInstance().calculateS(context.getApplicationContext(), srcArray, pin);
                str = sValue;
            } else {
                str = "";
            }
        }
        return str;
    }

    public static String getIValue(Context context) {
        if (TextUtils.isEmpty(sIValue)) {
            String deviceSerial = getImei(context);
            if (TextUtils.isEmpty(deviceSerial)) {
                deviceSerial = getWifiMac(context);
            }
            if (TextUtils.isEmpty(deviceSerial)) {
                deviceSerial = "000000000000000";
            }
            if (context != null && !TextUtils.isEmpty(deviceSerial)) {
                String iValue = getInstance().getIValue(context.getApplicationContext(), deviceSerial);
                sIValue = iValue;
                return iValue;
            }
            return "";
        }
        return sIValue;
    }

    public static String getImei(Context context) {
        if (TextUtils.isEmpty(sImei) && context != null) {
            if (PermissionUtils.hasSelfPermissions(WApplication.cContext, MsgConstant.PERMISSION_READ_PHONE_STATE)) {
                TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
                sImei = telephonyManager.getDeviceId();
            } else {
                sImei = null;
            }
        }
        return sImei;
    }

    public static String getWifiMac(Context context) {
        if (TextUtils.isEmpty(sMac) && context != null) {
            WifiManager wifi = (WifiManager) context.getApplicationContext().getSystemService(UtilityImpl.NET_TYPE_WIFI);
            WifiInfo mac = wifi.getConnectionInfo();
            sMac = mac != null ? mac.getMacAddress() : "";
        }
        return sMac;
    }
}
```

改类的大体分析如下

| 功能             | 方法                          | 说明                                   |
| ---------------- | ----------------------------- | -------------------------------------- |
| 加密计算         | calculateS / calculateSInJava | 基于种子和 PIN，生成加密签名           |
| 获取设备标识     | getImei, getWifiMac           | 尝试获取唯一设备标识（IMEI 或 MAC）    |
| 获取加密设备标识 | getIValue                     | 基于设备信息调用 native 加密逻辑生成值 |
| 单例管理         | getInstance                   | 保证类唯一实例，控制资源和缓存         |

接下来就是使用Frida hook这个方法，获取其入参和返回值，以下是hook脚本

```js
setTimeout(function () {
  Java.perform(function () {
    let WeiboSecurityUtils = Java.use(
      "com.sina.weibo.security.WeiboSecurityUtils"
    );
    WeiboSecurityUtils["calculateS"].implementation = function (
      context,
      str,
      str2
    ) {
      console.log(
        `WeiboSecurityUtils.calculateS is called: context=${context}, str=${str}, str2=${str2}`
      );
      let result = this["calculateS"](context, str, str2);
      console.log(`WeiboSecurityUtils.calculateS result=${result}`);
      return result;
    };
  });
}, 5000);
```

然后还是和上一篇文章**从实践中学习unidbg使用(一)**一样，主动使用获取到的入参进行附加进程主动调用该方法，然后获取到其返回值，再使用unidbg复现Frida hook的结果。主动调用的hook脚本可参考以下

```js
function callcalculateS() {
  Java.perform(function () {
    let WeiboSecurityUtils = Java.use(
      "com.sina.weibo.security.WeiboSecurityUtils"
    );
    let current_application = Java.use(
      "android.app.ActivityThread"
    ).currentApplication();
    let arg1 = current_application.getApplicationContext();
    let arg2 = "hello world";
    let arg3 = "123456";
    let ret = WeiboSecurityUtils.$new().calculateS(arg1, arg2, arg3);
    console.log("ret: " + ret);
  });
}
callcalculateS();
```

结果为 d74a75bb



### 三、初始化

```Java
package com.test1;

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

public class TEST1 extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmClass WeiboSecurityUtils;

    public TEST1() {
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.weico.international")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("D:\\Compilation_Enviroment\\unidbg-master\\unidbg-android\\src\\test\\java\\com\\test1\\sinaInternational.apk"));
        //设置当前类为虚拟机的JNI接口实现，即告诉虚拟机，如果 native 层调用 Java 方法、访问 Java 字段，使用我（这个类）来处理。
        vm.setJni(this);
        //打开 unidbg 的详细日志输出（verbose mode）
        vm.setVerbose(true);
        DalvikModule dm = vm.loadLibrary("utility", true);
        WeiboSecurityUtils = vm.resolveClass("com/sina/weibo/security/WeiboSecurityUtils");
        dm.callJNI_OnLoad(emulator);
    }

    public static void main(String[] args) {
        TEST1 test1 = new TEST1();
    }


}
```

apk lib 目录下只包含armeabi动态库，所以是ARM32。这篇讨论创建虚拟机对象、加载 SO 这两件事。

#### 3.1创建虚拟机

Unidbg的VM主要用于处理JNI逻辑，这里我们通过如下方式创建。

```Java
vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/weibo/sinaInternational.apk"));
```

**createDalvikVM**有两个重载方法，建议使用第二个。

```Java
//创建虚拟机
VM dalvikVM = emulator.createDalvikVM();
//创建虚拟机并指定APK文件
VM dalvikVM = emulator.createDalvikVM(new File("apk file path"));
```

加载APK这一行行为让很多人对Unidbg产生了误解，觉得它不是SO模拟器，而是应用级的模拟器，就像雷电或者夜神模拟器那样。

事实上，Unidbg加载APK并非要做执行DEX甚至是运行APK这样的大事，相反，它只是在做一些小事，主要包括下面两部分

1. 解析APK基本信息，减少使用者在补JNI环境上的工作量。Unidbg会解析APK的版本名、版本号、包名、APK签名等信息。如果样本通过JNI调用获取这些信息、Unidbg会替我们做处理。如果没有加载APK，这些逻辑就需要我们去补环境，平添了不少工作量。
2. 解析管理APK资源文件。加载APK后可以通过**openAsset**获取**APK assets**目录下的文件。如果样本通过**AAssetManager_open**等函数访问APK的**assets**，Unidbg会替我们做处理。

综上所述，创建虚拟机时加载APK会更省事。除此之外，Unidbg使用apk-parser这个开源项目完成APK的解析工作，读者可以在自己的项目里使用它。

```Java
<dependency>
    <groupId>net.dongliu</groupId>
    <artifactId>apk-parser</artifactId>
    <version>2.6.10</version>
</dependency>
```

#### 3.2加载SO

我们通过loadLibrary API将SO加载到Unidbg中，它有数个重载方法，下面两个使用最多。

```Java
//参数一: 动态库或可执行ELF文件
//参数二: 是否必须执行 init_proc、init_array 这些初始化函数
DalvikModule loadLibrary(File elfFile, boolean forceCallInit);

//参数一：动态库或可执行ELF的文件名
//参数二: 是否必须执行 init_proc、init_array 这些初始化函数
DalvikModule loadLibrary(String libname, boolean forceCallInit);
```

可以发现区别在于第一个参数，前者传入文件后者则传入动态库的名字。

后者在使用上近似于Java的**System.loadLibrary(soName)**，名字要掐头去尾，如libkwsgmain.so对应为kwsgmain。

```Java
vm.loadLibrary("kwsgmain", true);
```

loadLibrary内部会为libname再添头添尾。

```Java
@Override
public final DalvikModule loadLibrary(String libname, boolean forceCallInit) {
    String soName = "lib" + libname + ".so";
    LibraryFile libraryFile = findLibrary(soName);
    if (libraryFile == null) {
        throw new IllegalStateException("load library failed: " + libname);
    }
    Module module = emulator.getMemory().load(libraryFile, forceCallInit);
    return new DalvikModule(this, module);
}
```

只传入名字如何找到对应的SO文件并进行加载？这就依赖于3.1中所提到的加载APK，Unidbg会去APK的lib目录下寻找目标SO文件，如果不加载就没办法处理，下面看看具体代码。

首先是32位的处理，去找**armeabi-v7a**以及**armeabi**。

```Java
byte[] loadLibraryData(Apk apk, String soName) {
    byte[] soData = apk.getFileData("lib/armeabi-v7a/" + soName);
    if (soData != null) {
        if (log.isDebugEnabled()) {
            log.debug("resolve armeabi-v7a library: " + soName);
        }
        return soData;
    }
    soData = apk.getFileData("lib/armeabi/" + soName);
    if (soData != null && log.isDebugEnabled()) {
        log.debug("resolve armeabi library: " + soName);
    }
    return soData;
}
```

再看看64位，去**arm64-v8a**下找。

```Java
byte[] loadLibraryData(Apk apk, String soName) {
    byte[] soData = apk.getFileData("lib/arm64-v8a/" + soName);
    if (soData != null) {
        if (log.isDebugEnabled()) {
            log.debug("resolve arm64-v8a library: " + soName);
        }
        return soData;
    } else {
        return null;
    }
}
```

loadLibrary还有一个重载，直接传入字节数组。它的主要应用场景是加载从真实环境中Dump出的内存。

```Java
loadLibrary(String libname, byte[] raw, boolean forceCallInit)
```

这个API缺少维护和优化，并不好用。

在一般情况下，选择哪一个加载SO文件？我建议使用传入动态库名字的那一个，因为它能更好的处理SO的依赖模块。

#### 3.3加载依赖模块

几乎没有SO文件可以不依赖任何外部库就正常工作，比如各种各样的C标准库函数、Android FrameWork提供的一些库，以及样本的自定义库等等。

可以在IDA反汇编界面的头部查看依赖库信息，又或者使用objdump、readelf等工具也可以。
![image-20250603102021157](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250603102021157.png)

尽管都会依赖外部SO文件，但在这两篇文章里，我们似乎没有用到**loadLibrary**加载所需的这些SO文件。这是因为在SO的装载逻辑里，往往会解析依赖库，检查依赖库是否加载到当前内存中，如果未加载就尝试加载等等。

Android linker会这么做，Unidbg的ELF Loader当然也会这么做。尝试加载外部SO时，Android Linker会查找**/verdor/lib**这样的系统库目录以及**/data/app/packageName/base.apk!/lib/armeabi-v7a**这样的用户库目录。

Unidbg的ELF Loader也做了类似的处理，但逻辑上要简单很多。

对于系统库SO，Unidbg存在着一个系统库环境，包含着以libc.so为代表的常见SO文件。用户需要通过**setLibraryResolver**确认使用哪一个系统库文件，参数可选是23和19.

```Java
// 模拟器的内存操作接口
final Memory memory = emulator.getMemory();
// 设置系统类库
memory.setLibraryResolver(new AndroidResolver(23));
```

23 和 19 分别对应于 sdk23（Android 6.0） 和 sdk19（Android 4.4）的运行库环境。
![image-20250603102806733](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250603102806733.png)

处理64位的SO文件时只能选择SDK23，因为Android4.4以上没有对应的64位系统库。即使处理32位SO文件，我们一般都是用SDK23，因为它相对“新”一些。

如果读者希望使用更高版本的运行时库，可以参考**unidbg-android/pull.sh**，使用自己测试机的类库。但是，并非真机的SO放到Unidbg里就大功告成了，Unidbg为这两个环境做了一些优化和兼容性处理，比如多线程部分，你也需要做对应的处理才能让新环境可用。

接下来看看Unidbg寻找依赖SO的代码逻辑

```Java
LibraryFile neededLibraryFile = libraryFile.resolveLibrary(emulator, neededLibrary);
if (libraryResolver != null && neededLibraryFile == null) {
    neededLibraryFile = libraryResolver.resolveLibrary(emulator, neededLibrary);
}
```

第二处的**resolveLibrary**用于寻找系统库路径下是否有对应的SO，如下所示：

```Java
protected static LibraryFile resolveLibrary(Emulator<?> emulator, String libraryName, int sdk, Class<?> resClass) {
    final String lib = emulator.is32Bit() ? "lib" : "lib64";
    String name = "/android/sdk" + sdk + "/" + lib + "/" + libraryName.replace('+', 'p');
    URL url = resClass.getResource(name);
    if (url != null) {
        return new URLibraryFile(url, libraryName, sdk, emulator.is64Bit());
    }
    return null;
}
```

第一处**resolveLibrary**用于寻找用户库路径下是否有对应SO文件，如下所示。上一小节说用libname比libFile更适合处理依赖模块的原因就在这里。

如果采用libFile方法加载，那就会在libFile的统计目录下寻找对应SO文件。

```Java
@Override
public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) {
    File file = new File(elfFile.getParentFile(), soName);
    return file.canRead() ? new ElfLibraryFile(file, is64Bit) : null;
}
```

如果采用libname方法加载，那就会在lib目录下寻找对应的SO文件。

```Java
@Override
public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) {
    byte[] libData = baseVM.loadLibraryData(apk, soName);
    return libData == null ? null : new ApkLibraryFile(baseVM, this.apk, soName, libData, packageName, is64Bit);
}

// 32 位
byte[] loadLibraryData(Apk apk, String soName) {
    byte[] soData = apk.getFileData("lib/armeabi-v7a/" + soName);
    if (soData != null) {
        if (log.isDebugEnabled()) {
            log.debug("resolve armeabi-v7a library: " + soName);
        }
        return soData;
    }
    soData = apk.getFileData("lib/armeabi/" + soName);
    if (soData != null && log.isDebugEnabled()) {
        log.debug("resolve armeabi library: " + soName);
    }
    return soData;
}
```

那么使用libFile加载时，使用者不仅要在lib下拷贝出目标SO文件，最好也将其他的SO拷贝出来，以防存在依赖，通过libname加载则不需要考虑这个问题。
当然也可以采用手动加载多个SO文件，像下面这样。

```Java
vm.loadLibrary("kwsgmain", true);
vm.loadLibrary("abc", true);
```



### 四、发起调用

```Java
public String callcalculateS(){
	DvmObject<?> context = vm.resolveClass("android/app/Application", vm.resolveClass("android/content/ContextWrapper", vm.resolveClass("android/content/Context"))).newObject(null);
	String arg2 = "hello world";
    String arg3 = "123456";
    String ret = WeiboSecurityUtils.newObject(null).callJniMethodObject(emulator, "calculateS", context, arg2, arg3).getValue().toString();
    return ret;
}
```

参数2、3都是字符串，按照前篇所述直接传入就行。

参数1时Android中最常见的Context，为什么要这么处理？这样处理相当微妙，我们在后面的文章里讨论它。

运行报错如下

```bash
JNIEnv->FindClass(android/content/pm/PackageManager) was called from RX@0x12002c79[libutility.so]0x2c79
[15:58:55 618]  WARN [com.github.unidbg.linux.ARM32SyscallHandler] (ARM32SyscallHandler:538) - handleInterrupt intno=2, NR=0, svcNumber=0x11e, PC=unidbg@0xfffe0274, LR=RX@0x12002c8d[libutility.so]0x2c8d, syscall=null
java.lang.UnsupportedOperationException: android/content/ContextWrapper->getPackageManager()Landroid/content/pm/PackageManager;
	at com.github.unidbg.linux.android.dvm.AbstractJni.callObjectMethod(AbstractJni.java:933)
	at com.github.unidbg.linux.android.dvm.AbstractJni.callObjectMethod(AbstractJni.java:867)
	at com.github.unidbg.linux.android.dvm.DvmMethod.callObjectMethod(DvmMethod.java:69)
```

报错原因就是我们在模拟执行的时候没有实现**getPackageManager**函数，因此我们需要在**callObjectMethod**函数中实现这个函数，简单的实现则是返回它所需要的值(一般用于占位即可)，补环境代码如下。函数签名已经在报错中了，可以直接使用。

```Java
@Override
public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
    switch (signature){
        case "android/content/ContextWrapper->getPackageManager()Landroid/content/pm/PackageManager;":{
            return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
        }
    }
    return super.callObjectMethod(vm, dvmObject, signature, varArg);
}
```

继续运行，出现报错
![image-20250603160922255](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250603160922255.png)

这个意思是传递给free函数的地址0x12175000是无效的，导致内存释放失败。遇到这个报错，最简单的处理办法就是 hook free 函数，替换它的实现，让它返回 0，即释放成功。当然也可以对报错的待释放内存做处理，比如只有指针地址是 0x12175000 释放失败时。

patch代码如下

```Java
public void patchFree(){
        IWhale whale = Whale.getInstance(emulator);
        Symbol free = memory.findModule("libc.so").findSymbolByName("free");

        whale.inlineHookFunction(free, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                System.out.println("WInlineHookFunction free = " + emulator.getContext().getPointerArg(0));
                long addr = emulator.getContext().getPointerArg(0).peer;
                if (addr == 0x12175000 || addr == 0x12176000){
                    return HookStatus.LR(emulator, 0);
                }
                else {
                    return HookStatus.RET(emulator,originFunction);
                }

            }
        });
    }
```

完整代码如下。

```Java
package com.test1;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.whale.IWhale;
import com.github.unidbg.hook.whale.Whale;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import unicorn.ArmConst;

import java.io.File;

public class TEST1 extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmClass WeiboSecurityUtils;
    private final Memory memory;

    public TEST1() {
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.weico.international")
                .build();
        memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("D:\\Compilation_Enviroment\\unidbg-master\\unidbg-android\\src\\test\\java\\com\\test1\\sinaInternational.apk"));
        //设置当前类为虚拟机的JNI接口实现，即告诉虚拟机，如果 native 层调用 Java 方法、访问 Java 字段，使用我（这个类）来处理。
        vm.setJni(this);
        //打开 unidbg 的详细日志输出（verbose mode）
        vm.setVerbose(true);
        DalvikModule dm = vm.loadLibrary("utility", true);

        WeiboSecurityUtils = vm.resolveClass("com/sina/weibo/security/WeiboSecurityUtils");
        dm.callJNI_OnLoad(emulator);

        patchFree();
    }

    public String callS(){
        DvmObject<?> context = vm.resolveClass("android/app/Application", vm.resolveClass("android/content/ContextWrapper", vm.resolveClass("android/content/Context"))).newObject(null);
        String arg2 = "hello world";
        String arg3 = "123456";
        // String ret =
        return  WeiboSecurityUtils.newObject(null).callJniMethodObject(emulator, "calculateS", context, arg2, arg3).getValue().toString();
    }

    public static void main(String[] args) {
        TEST1 test1 = new TEST1();
        String result = test1.callS();
        System.out.println("call s result:"+result);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature){
            case "android/content/ContextWrapper->getPackageManager()Landroid/content/pm/PackageManager;":{
                return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
            }
        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    public void patchFree(){
        IWhale whale = Whale.getInstance(emulator);
        Symbol free = memory.findModule("libc.so").findSymbolByName("free");

        whale.inlineHookFunction(free, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                System.out.println("WInlineHookFunction free = " + emulator.getContext().getPointerArg(0));
                long addr = emulator.getContext().getPointerArg(0).peer;
                if (addr == 0x12175000 || addr == 0x12176000){
                    return HookStatus.LR(emulator, 0);
                }
                else {
                    return HookStatus.RET(emulator,originFunction);
                }

            }
        });
    }


}
```

运行结果

```bash
call s result:d74a75bb
```

#### 参考

[Unidbg 的基本使用（二）](https://www.yuque.com/lilac-2hqvv/xdwlsg/vy2p4ts1oq8sxxgb?# 《Unidbg 的基本使用（二）》)

[补库函数（五）](https://www.yuque.com/lilac-2hqvv/xdwlsg/bzoykwvuim3hkz2o?# 《补库函数（五）》)
