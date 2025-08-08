---
title: 从实践中学习unidbg使用(四)
tags: [Unidbg]
categories: Unidbg学习
---

# 从实践中学习unidbg使用(四)

### 一、引言

本篇中的APK详见参考文章中

目标APK：bilibili.apk

目标方法实：libbili.so



### 二、任务介绍

**JADX**反编译.apk，找到**com.bilibili.nativelibrary.LibBili**类，其中的 s 方法是本篇的目标函数。它是一个静态方法，参数是Map，返回值是 SignedQuery 对象。

```Java
package com.bilibili.nativelibrary;

import androidx.annotation.NonNull;
import com.bilibili.lib.media.resource.PlayIndex;
import java.io.UnsupportedEncodingException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* compiled from: BL */
/* loaded from: classes.dex */
public final class LibBili {
    public static final int a = 0;
    public static final int b = 1;

    /* renamed from: c, reason: collision with root package name */
    public static final int f14891c = 0;
    public static final int d = 1;
    public static final int e = 2;
    public static final int f = 3;

    /* compiled from: BL */
    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface a {
    }

    /* compiled from: BL */
    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface b {
    }

    static {
        com.getkeepsafe.relinker.c.c(PlayIndex.G);
    }

    private static native String a(String str);

    private static native String ao(String str, int i2, int i3);

    private static native IvParameterSpec b(String str) throws InvalidKeyException;

    public static byte[] b(String str, byte[] bArr) throws InvalidKeyException {
        try {
            byte[] bytes = str.getBytes("UTF-8");
            return com.bilibili.nativelibrary.a.a(new SecretKeySpec(Arrays.copyOf(bytes, 16), "AES"), b(str), bArr);
        } catch (UnsupportedEncodingException | Exception unused) {
            return bArr;
        }
    }

    public static byte[] c(String str, byte[] bArr) throws InvalidKeyException {
        try {
            byte[] bytes = str.getBytes("UTF-8");
            return com.bilibili.nativelibrary.a.b(new SecretKeySpec(Arrays.copyOf(bytes, 16), "AES"), b(str), bArr);
        } catch (UnsupportedEncodingException | Exception unused) {
            return bArr;
        }
    }

    @Deprecated
    public static String d() {
        return e("android");
    }

    public static String e(String str) {
        return a(str);
    }

    public static String f(String str, int i2, int i3) {
        return ao(str, i2, i3);
    }

    public static SignedQuery g(Map<String, String> map) {
        return s(map == null ? new TreeMap() : new TreeMap(map));
    }

    public static native int getCpuCount();

    @Deprecated
    public static native int getCpuId();

    public static SignedQuery h(Map<String, String> map, int i2, int i3) {
        TreeMap treeMap;
        if (map == null) {
            treeMap = new TreeMap();
        } else {
            treeMap = new TreeMap(map);
        }
        return so(treeMap, i2, i3);
    }

    public static SignedQuery i(Map<String, String> map, @NonNull byte[] bArr) {
        TreeMap treeMap;
        if (map == null) {
            treeMap = new TreeMap();
        } else {
            treeMap = new TreeMap(map);
        }
        return so(treeMap, bArr);
    }

    static native SignedQuery s(SortedMap<String, String> sortedMap);

    static native SignedQuery so(SortedMap<String, String> sortedMap, int i2, int i3);

    static native SignedQuery so(SortedMap<String, String> sortedMap, byte[] bArr);
}
```

该类是样本应用中的一个JNI桥接类，主要作用是为Java层提供对native层加密/签名/系统信息处理等能力的访问。

而我们的目标函数在LibBili类里的g函数使用了它。

```Java
public static SignedQuery g(Map<String, String> map) {
	return s(map == null ? new TreeMap() : new TreeMap(map));
}
```

对 g 方法做hook，参考代码如下

```js
function hookS() {
    setTimeout(function () {
        Java.perform(function () {
            let LibBili = Java.use("com.bilibili.nativelibrary.LibBili");
            let Map = Java.use("java.util.HashMap");
            
            LibBili["g"].implementation = function (map) {
                console.log('g is called' + ' map: ' + Java.cast(map, Map));
                let ret = this.g(map);
                console.log('g ret value is ' + ret + '\n');
                return ret;
            };

        });
    }, 3000);
}

hookS();
```

输出有很多，随便取一条

```shell
g is called map: {build=6180500, mobi_app=android, channel=shenma069, actionKey=appkey, appkey=1d8b6e7d45233436, s_locale=zh_CN, c_locale=zh_CN, device=android, hash=97fa29af-c53f-0712-1701-5271-ac82-ba11-8af1-6e8a-943b-5e5b, platform=android, statistics={"appId":1,"platform":3,"version":"6.18.0","abtest":""}}

g ret value is actionKey=appkey&appkey=1d8b6e7d45233436&build=6180500&c_locale=zh_CN&channel=shenma069&device=android&hash=97fa29af-c53f-0712-1701-5271-ac82-ba11-8af1-6e8a-943b-5e5b&mobi_app=android&platform=android&s_locale=zh_CN&statistics=%7B%22appId%22%3A1%2C%22platform%22%3A3%2C%22version%22%3A%226.18.0%22%2C%22abtest%22%3A%22%22%7D&ts=1752200177&sign=19d4104c2956d248dc02fb12b8c076de
```

返回值是SignedQuery对象，打印发现直接返回了字符串，这是因为SignedQuery里重写了toString方法，如下所示：

```Java
package com.bilibili.nativelibrary;

import android.text.TextUtils;
import com.huawei.hms.framework.common.ContainerUtils;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import u.aly.cv;

public final class SignedQuery {
    private static final char[] f14891c = "0123456789ABCDEF".toCharArray();
    public final String a;
    public final String b;

    public SignedQuery(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public String toString() {
        String str = this.a;
        if (str == null) {
            return "";
        }
        if (this.b == null) {
            return str;
        }
        return this.a + "&sign=" + this.b;
    }
}
```

使用Frida Call主动调用一下

```js
function callS() {
        Java.perform(function () {
            let LibBili = Java.use("com.bilibili.nativelibrary.LibBili");
            let TreeMap = Java.use("java.util.TreeMap");
			var map = TreeMap.$new();
            
            map.put("build", "6180500");
			map.put("mobi_app", "android");
			map.put("channel", "shenma069");
			map.put("appkey", "1d8b6e7d45233436");
			map.put("s_locale", "zh_CN");

			let result = LibBili.s(map);
			console.log("ret: " + result);

        });

}
callS();
```

其中map的键值对可以多一些也可以少一些。然后经过多次调用

```shell
ret: appkey=1d8b6e7d45233436&build=6180500&channel=shenma069&device=&mobi_app=android&s_locale=zh_CN&ts=1752201522&sign=34bd4782c3ac27818b28140f10acdfe7
ret: appkey=1d8b6e7d45233436&build=6180500&channel=shenma069&device=android&mobi_app=android&s_locale=zh_CN&ts=1752201525&sign=08a09f59ffa5622895206c837947444c
ret: appkey=1d8b6e7d45233436&build=6180500&channel=shenma069&device=android&mobi_app=android&s_locale=zh_CN&ts=1752201526&sign=0c769ea4759665c8fac80c8fd49f0f12
ret: appkey=1d8b6e7d45233436&build=6180500&channel=shenma069&device=android&mobi_app=android&s_locale=zh_CN&ts=1752201529&sign=04e9de2cba349039d74cdb65c0f643ad
ret: appkey=1d8b6e7d45233436&build=6180500&channel=shenma069&device=android&mobi_app=android&s_locale=zh_CN&ts=1752201530&sign=ea183695d071bbda958745a20d09e9ed
```

可以观察到，返回的值由八个键值对组成，六个来自输入，ts是时间戳，还有一个就是sign。本篇的目标就是使用Unidbg复现对sign的调用。



### 三、初始化

初始化代码如下

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

因为担心可能存在文件访问，所以这里继承了 IOResolver，补文件访问的相关处理见 《补文件访问》专题的相关文章。

运行代码，发现并没有像参考文章中报错，但是如果加了多线程处理的逻辑，输出会有变化。

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

参考文章中的报错试因为，如果样本调用了多线程创建函数 **pthread_create**，但Unidbg未开启多线程处理逻辑，就会报这个错，所以需要开启多线程逻辑。代码如上。

而这个报错背后的逻辑，是因为样本在调用 **pthread_create** 创建线程时，最终会走到clone系统调用，在Unidbg中对应于 **bionic_clone** 函数，对应于下面的逻辑

```Java
if (threadDispatcherEnabled) {
    if (verbose) {
        System.out.printf("bionic_clone fn=%s%n", fn);
    }
    emulator.getThreadDispatcher().addThread(new MarshmallowThread(emulator, fn, arg, ctid, threadId));
    ctid.setInt(0, threadId);
    return threadId;
}
emulator.getMemory().setErrno(UnixEmulator.ENOMEM);
return -UnixEmulator.ENOMEM;
```

即如果打开了多线程，就添加新线程，进入调度逻辑，否则就设置错误码为 **ENOMEM** ，它进而导致 **Out of memory** 的报错，提醒我们开启多线程处理逻辑。

```Java
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

言归正传，继续运行，依然没有报错，Unidbg的日志输出中可以看到 s 方法，它来自于动态注册。

**(Ljava/util/SortedMap;)Lcom/bilibili/nativelibrary/SignedQuery;**  就是待会调用它的签名。

```shell
JNIEnv->RegisterNatives(com/bilibili/nativelibrary/LibBili, RW@0x1200b004[libbili.so]0xb004, 8) was called from RX@0x12001b8f[libbili.so]0x1b8f
RegisterNative(com/bilibili/nativelibrary/LibBili, a(Ljava/lang/String;)Ljava/lang/String;, RX@0x12001c7d[libbili.so]0x1c7d)
RegisterNative(com/bilibili/nativelibrary/LibBili, ao(Ljava/lang/String;II)Ljava/lang/String;, RX@0x12001c83[libbili.so]0x1c83)
RegisterNative(com/bilibili/nativelibrary/LibBili, b(Ljava/lang/String;)Ljavax/crypto/spec/IvParameterSpec;, RX@0x12001c91[libbili.so]0x1c91)
RegisterNative(com/bilibili/nativelibrary/LibBili, s(Ljava/util/SortedMap;)Lcom/bilibili/nativelibrary/SignedQuery;, RX@0x12001c97[libbili.so]0x1c97)
RegisterNative(com/bilibili/nativelibrary/LibBili, so(Ljava/util/SortedMap;II)Lcom/bilibili/nativelibrary/SignedQuery;, RX@0x12001c9d[libbili.so]0x1c9d)
RegisterNative(com/bilibili/nativelibrary/LibBili, so(Ljava/util/SortedMap;[B)Lcom/bilibili/nativelibrary/SignedQuery;, RX@0x12001cab[libbili.so]0x1cab)
RegisterNative(com/bilibili/nativelibrary/LibBili, getCpuCount()I, RX@0x12001cb3[libbili.so]0x1cb3)
RegisterNative(com/bilibili/nativelibrary/LibBili, getCpuId()I, RX@0x12001cb7[libbili.so]0x1cb7)
```



### 四、发起调用

我们前面的例子里，参数和返回值都是基本类型、字符串、字节数组，直接传入就可以调用
而这里比较特殊，是个map，读者可能也想到这样调用

```Java
public String callS(){
    TreeMap<String, String> map = new TreeMap<>();
    map.put("build", "6180500");
    map.put("mobi_app", "android");
    map.put("channel", "shenma069");
    map.put("appkey", "1d8b6e7d45233436");
    map.put("s_locale", "zh_CN");
    map.put("device", "android");
    String ret = LibBili.callStaticJniMethodObject(emulator, "s(Ljava/util/SortedMap;)Lcom/bilibili/nativelibrary/SignedQuery;", map).getValue().toString();
    return ret;
}
```

运行发现报错 Unsupported arg

```Java
Exception in thread "main" java.lang.IllegalStateException: Unsupported arg: {appkey=1d8b6e7d45233436, build=6180500, channel=shenma069, device=android, mobi_app=android, s_locale=zh_CN}
	at com.github.unidbg.Module.emulateFunction(Module.java:160)
	at com.github.unidbg.linux.android.dvm.DvmObject.callJniMethod(DvmObject.java:135)
	at com.github.unidbg.linux.android.dvm.DvmClass.callStaticJniMethodObject(DvmClass.java:316)
	at com.test3.TEST3.callS(TEST3.java:69)
	at com.test3.TEST3.main(TEST3.java:52)
```

接下里完整地学习一下 Unidbg 中JNI对象的方法，

首先根据 **JNI** 标准，**JNI** 方法的返回值，以及 JAVA 传递到 **Native** 的对象，都是 **JObject** ，其中最常用的一些类还做了细分，具体情况如下。
![image-20250712113706002](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250712113706002.png)

jclass是类对象，jstring 是字符串，jarray 以及其他细分是各种各样的数组， jthrowable 是 JNI 异常处理中使用到的对象。

在Unidbg中，做了几乎完整的等价模拟和映射。

- jobject 对应于 DvmOgject
- jclass 对应于 DvmClass
- jstring 对应于 StringObject
- jarray 对应于 BaseArray
- jobjectArray 对应于 ByteArray
- jshortArray 对应于 ShortArray
- jintArray 对应于 IntArray

在补 JNI 调用时，如果返回值是String，需要封装为 StringObject ，比如前文就有一个片段，返回了字符串。

```Java
case "java/lang/Class->getSimpleName()Ljava/lang/String;":{
    String className = ((DvmClass) dvmObject).getClassName();
    String[] name = className.split("/");
    return new StringObject(vm, name[name.length - 1]);
}
```

在函数调用时，为什么字符串、字节数组这样的对象，我们不需要用**StringObject** 以及 **ByteArray** 包装？

**callXXX** 系列方法内部调用了 **callJniMethod** 方法，不妨解析一下这个代码。

```Java
protected static Number callJniMethod(Emulator<?> emulator, VM vm, DvmClass objectType, DvmObject<?> thisObj, String method, Object...args) {
    UnidbgPointer fnPtr = objectType.findNativeFunction(emulator, method);
    vm.addLocalObject(thisObj);
    List<Object> list = new ArrayList<>(10);
    list.add(vm.getJNIEnv());
    list.add(thisObj.hashCode());
    if (args != null) {
        for (Object arg : args) {
            if (arg instanceof Boolean) {
                list.add((Boolean) arg ? VM.JNI_TRUE : VM.JNI_FALSE);
                continue;
            } else if(arg instanceof Hashable) {
                list.add(arg.hashCode()); // dvm object

                if(arg instanceof DvmObject) {
                    vm.addLocalObject((DvmObject<?>) arg);
                }
                continue;
            } else if (arg instanceof DvmAwareObject ||
                    arg instanceof String ||
                    arg instanceof byte[] ||
                    arg instanceof short[] ||
                    arg instanceof int[] ||
                    arg instanceof float[] ||
                    arg instanceof double[] ||
                    arg instanceof Enum) {
                DvmObject<?> obj = ProxyDvmObject.createObject(vm, arg);
                list.add(obj.hashCode());
                vm.addLocalObject(obj);
                continue;
            }

            list.add(arg);
        }
    }
    return Module.emulateFunction(emulator, fnPtr.peer, list.toArray());
}
```

它首先根据方法签名找到对应的函数地址，这个逻辑在 findNativeFunction里。

```Java
UnidbgPointer fnPtr = objectType.findNativeFunction(emulator, method);
```

接着开始处理函数参数，首先添加 JNIEnv、Jobject/Jclass 作为第一、二个参数，这是 JNI 规范的默认要求。

```Java
List<Object> list = new ArrayList<>(10);
list.add(vm.getJNIEnv());
list.add(thisObj.hashCode());
```

然后处理函数自己的入参

```Java
if (args != null) {
    for (Object arg : args) {
        if (arg instanceof Boolean) {
            list.add((Boolean) arg ? VM.JNI_TRUE : VM.JNI_FALSE);
            continue;
        } else if(arg instanceof Hashable) {
            list.add(arg.hashCode()); // dvm object

            if(arg instanceof DvmObject) {
                vm.addLocalObject((DvmObject<?>) arg);
            }
            continue;
        } else if (arg instanceof DvmAwareObject ||
                arg instanceof String ||
                arg instanceof byte[] ||
                arg instanceof short[] ||
                arg instanceof int[] ||
                arg instanceof float[] ||
                arg instanceof double[] ||
                arg instanceof Enum) {
            DvmObject<?> obj = ProxyDvmObject.createObject(vm, arg);
            list.add(obj.hashCode());
            vm.addLocalObject(obj);
            continue;
        }

        list.add(arg);
    }
}
```

其中包含 Boolean 转为 01，添加局部引用，判断是否已经是 **DvmObject** 等一系列逻辑，再下面就是对常见类型的包装，如果用户传入 String 、byteArray等类型，会通过 **ProxyDvmObject.createObject** 自动装箱为 Unidbg JNI 中对应的类型。我们注意到， **callJniMethod** 没有处理参数是Map 的情况，所以没能经过自动装箱。

```Java
public static DvmObject<?> createObject(VM vm, Object value) {
    if (value == null) {
        return null;
    }
    if (value instanceof Class<?>) {
        return getObjectType(vm, (Class<?>) value);
    }
    if (value instanceof DvmObject) {
        return (DvmObject<?>) value;
    }

    if (value instanceof byte[]) {
        return new ByteArray(vm, (byte[]) value);
    }
    if (value instanceof short[]) {
        return new ShortArray(vm, (short[]) value);
    }
    if (value instanceof int[]) {
        return new IntArray(vm, (int[]) value);
    }
    if (value instanceof float[]) {
        return new FloatArray(vm, (float[]) value);
    }
    if (value instanceof double[]) {
        return new DoubleArray(vm, (double[]) value);
    }
    if (value instanceof String) {
        return new StringObject(vm, (String) value);
    }
    Class<?> clazz = value.getClass();
    if (clazz.isArray()) {
        if (clazz.getComponentType().isPrimitive()) {
            throw new UnsupportedOperationException(String.valueOf(value));
        }
        Object[] array = (Object[]) value;
        DvmObject<?>[] dvmArray = new DvmObject[array.length];
        for (int i = 0; i < array.length; i++) {
            dvmArray[i] = createObject(vm, array[i]);
        }
        return new ArrayObject(dvmArray);
    }

    return new ProxyDvmObject(vm, value);
}
```

但事实上， **createObject** 除了可以处理 String、array这样的普通对象，也可以处理 map 或其他对象类型。来看 **ProxyDvmObject** 对象的构造逻辑，它会对类的父类以及接口类做解析，嵌套式的**getObjectType**，最后 **resolveClass** 再 **newObject** 得到最终的 **DvmObject**。

```Java
private ProxyDvmObject(VM vm, Object value) {
    super(getObjectType(vm, value.getClass()), value);
}

private static DvmClass getObjectType(VM vm, Class<?> clazz) {
    Class<?> superClass = clazz.getSuperclass();
    DvmClass[] interfaces = new DvmClass[clazz.getInterfaces().length + (superClass == null ? 0 : 1)];
    int i = 0;
    if (superClass != null) {
        interfaces[i++] = getObjectType(vm, superClass);
    }
    for (Class<?> cc : clazz.getInterfaces()) {
        interfaces[i++] = getObjectType(vm, cc);
    }
    return vm.resolveClass(clazz.getName().replace('.', '/'), interfaces);
}
```

因此我们手动调用它处理 map

```Java
public String callS(){
    TreeMap<String, String> map = new TreeMap<>();
    map.put("build", "6180500");
    map.put("mobi_app", "android");
    map.put("channel", "shenma069");
    map.put("appkey", "1d8b6e7d45233436");
    map.put("s_locale", "zh_CN");
    DvmObject<?> mapObject = ProxyDvmObject.createObject(vm, map);
    String ret = LibBili.callStaticJniMethodObject(emulator, "s(Ljava/util/SortedMap;)Lcom/bilibili/nativelibrary/SignedQuery;", mapObject).getValue().toString();
    return ret;
}
```

不妨总结一下补 JNI 的形式要求

- 基本类型直接传递
- 字符串、字节数组等基本对象直接传递，其内部会做封装，也可以自己调用 **new StringObject(vm, str)**、**new ByteArray(vm, value)**等。
- JDK 标准库对象，如 HashMap、JsonObject 等，使用 **ProxyDvmObject.createObject(vm, value)** 处理。
- 非 JDK 标准对象，如 Android Context、SharedPreference 等，使用 **vm.resolveClass(vm, className).newObject(vlaue)** 处理。

接下来按照这样的形式要求去实践补环境



### 五、补环境

运行报错

```shell
[13:30:16 216]  WARN [com.github.unidbg.AbstractEmulator] (AbstractEmulator:417) - emulate RX@0x12001c97[libbili.so]0x1c97 exception sp=unidbg@0xe4fff648, msg=java/util/Map->isEmpty()Z, offset=9ms @ Runnable|Function32 address=0x12001c97, arguments=[unidbg@0xfffe12a0, -288775324, 2100961961]
Exception in thread "main" java.lang.NullPointerException: Cannot invoke "com.github.unidbg.linux.android.dvm.DvmObject.getValue()" because the return value of "com.github.unidbg.linux.android.dvm.DvmClass.callStaticJniMethodObject(com.github.unidbg.Emulator, String, Object[])" is null
	at com.test3.TEST3.callS(TEST3.java:68)
	at com.test3.TEST3.main(TEST3.java:50)
```

isEmpty 用于判断 Map 是否为空，取出这个 dvmObject 对应的 map 对象，调用它的 isEmpty 方法。

```Java
@Override
public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
    switch (signature){
        case "java/util/Map->isEmpty()Z":{
            Map map = (Map) dvmObject.getValue();
            return map.isEmpty();
        }
    }
    return super.callBooleanMethod(vm, dvmObject, signature, varArg);
}
```

继续运行

```shell
[13:48:32 772]  WARN [com.github.unidbg.AbstractEmulator] (AbstractEmulator:417) - emulate RX@0x12001c97[libbili.so]0x1c97 exception sp=unidbg@0xe4fff648, msg=java/util/Map->get(Ljava/lang/Object;)Ljava/lang/Object;, offset=8ms @ Runnable|Function32 address=0x12001c97, arguments=[unidbg@0xfffe12a0, -288775324, 2100961961]
Exception in thread "main" java.lang.NullPointerException: Cannot invoke "com.github.unidbg.linux.android.dvm.DvmObject.getValue()" because the return value of "com.github.unidbg.linux.android.dvm.DvmClass.callStaticJniMethodObject(com.github.unidbg.Emulator, String, Object[])" is null
	at com.test3.TEST3.callS(TEST3.java:69)
	at com.test3.TEST3.main(TEST3.java:51)
```

同样实现它。不以 **V** 结尾的 JNI 函数通过varArg 取参数，以 **V** 结尾的 JNI 函数中通过carList取参数。

getObjectArg(index) 用于获取第 **index** 个 **object** 参数，如果是 int、long 等类型需要使用对应的 **getintArg** 、**getlongArg** 等等。

```Java
@Override
public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
    switch (signature){
        case "java/util/Map->get(Ljava/lang/Object;)Ljava/lang/Object;":{
            Map map = (Map) dvmObject.getValue();
            // 不要忘了getvalue
            Object key = varArg.getObjectArg(0).getValue();
            return ProxyDvmObject.createObject(vm, map.get(key));
        }
    }
    return super.callObjectMethod(vm, dvmObject, signature, varArg);
}
```

继续运行

```shell
[14:07:40 615]  WARN [com.github.unidbg.AbstractEmulator] (AbstractEmulator:417) - emulate RX@0x12001c97[libbili.so]0x1c97 exception sp=unidbg@0xe4fff610, msg=java/util/Map->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;, offset=23ms @ Runnable|Function32 address=0x12001c97, arguments=[unidbg@0xfffe12a0, -288775324, 2100961961]
Exception in thread "main" java.lang.NullPointerException: Cannot invoke "com.github.unidbg.linux.android.dvm.DvmObject.getValue()" because the return value of "com.github.unidbg.linux.android.dvm.DvmClass.callStaticJniMethodObject(com.github.unidbg.Emulator, String, Object[])" is null
	at com.test3.TEST3.callS(TEST3.java:69)
	at com.test3.TEST3.main(TEST3.java:51)
```

同样还是实现它

```Java
case "java/util/Map->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;":{
    Map map = (Map) dvmObject.getValue();
    Object key = varArg.getObjectArg(0).getValue();
    Object value = varArg.getObjectArg(1).getValue();
    return ProxyDvmObject.createObject(vm, map.put(key, value));
}
```

继续运行，这次报错比较特殊

```shell
[14:18:20 309]  WARN [com.github.unidbg.AbstractEmulator] (AbstractEmulator:417) - emulate RX@0x12001c97[libbili.so]0x1c97 exception sp=unidbg@0xe4fff658, msg=com/bilibili/nativelibrary/SignedQuery->r(Ljava/util/Map;)Ljava/lang/String;, offset=16ms @ Runnable|Function32 address=0x12001c97, arguments=[unidbg@0xfffe12a0, -288775324, 2100961961]
Exception in thread "main" java.lang.NullPointerException: Cannot invoke "com.github.unidbg.linux.android.dvm.DvmObject.getValue()" because the return value of "com.github.unidbg.linux.android.dvm.DvmClass.callStaticJniMethodObject(com.github.unidbg.Emulator, String, Object[])" is null
	at com.test3.TEST3.callS(TEST3.java:69)
	at com.test3.TEST3.main(TEST3.java:51)
```

这是样本中自定义的函数，在JADX中看它的代码逻辑。

```Java
static String r(Map<String, String> map) {
        if (!(map instanceof SortedMap)) {
            map = new TreeMap(map);
        }
        StringBuilder sb = new StringBuilder(256);
        for (Map.Entry<String, String> entry : map.entrySet()) {
            String key = entry.getKey();
            if (!TextUtils.isEmpty(key)) {
                sb.append(b(key));
                sb.append(ContainerUtils.KEY_VALUE_DELIMITER);
                String value = entry.getValue();
                sb.append(value == null ? "" : b(value));
                sb.append(ContainerUtils.FIELD_DELIMITER);
            }
        }
        int length = sb.length();
        if (length > 0) {
            sb.deleteCharAt(length - 1);
        }
        if (length == 0) {
            return null;
        }
        return sb.toString();
    }
```

将其直接粘贴到 Unidbg 里，但似乎有些问题
导入 SortedMap

```java
import java.util.SortedMap;
```

TextUtils 是 Android FrameWork 中用于处理文本的工具类，TextUtils.isEmpty 和 string.isEmpty功能类似，这里直接替换。
![image-20250713143833414](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250713143833414.png)

b 方法是 **SignedQuery** 类里另一个方法，我们干脆把 **SignedQuery** 以及 ContainerUtils 这两个类从 JADX 中拷贝过来，以免遗漏，在这个过程中发现依赖 **cv.m**。

![image-20250713144234405](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250713144234405.png)

这个字段是 15，直接硬编码处理一下
![image-20250713144314751](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250713144314751.png)

移过来的 **ContainerUtils** 内容如下

```Java
package com.Bili;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ContainerUtils {
    public static final String FIELD_DELIMITER = "&";
    public static final String KEY_VALUE_DELIMITER = "=";

    public static <K, V> boolean equals(Map<K, V> map, Map<K, V> map2) {
        if (map == map2) {
            return true;
        }
        boolean z = false;
        if (map == null || map2 == null || map.size() != map2.size()) {
            return false;
        }
        Iterator<Map.Entry<K, V>> it = map.entrySet().iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            Map.Entry<K, V> next = it.next();
            if (map2.get(next.getKey()) != next.getValue()) {
                z = true;
                break;
            }
        }
        return !z;
    }

    public static <K, V> int hashCode(Map<K, V> map) {
        return toString(map).hashCode();
    }

    public static <K> String toString(List<K> list) {
        if (list == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int i2 = 0;
        for (K k : list) {
            int i3 = i2 + 1;
            if (i2 > 0) {
                sb.append(FIELD_DELIMITER);
            }
            sb.append(k.toString());
            i2 = i3;
        }
        return sb.toString();
    }

    public static <K, V> String toString(Map<K, V> map) {
        if (map == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int i2 = 0;
        for (Map.Entry<K, V> entry : map.entrySet()) {
            int i3 = i2 + 1;
            if (i2 > 0) {
                sb.append(FIELD_DELIMITER);
            }
            sb.append(entry.getKey().toString());
            sb.append(KEY_VALUE_DELIMITER);
            sb.append(entry.getValue().toString());
            i2 = i3;
        }
        return sb.toString();
    }

    public static <K> String toString(Set<K> set) {
        if (set == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int i2 = 0;
        for (K k : set) {
            int i3 = i2 + 1;
            if (i2 > 0) {
                sb.append(FIELD_DELIMITER);
            }
            sb.append(k.toString());
            i2 = i3;
        }
        return sb.toString();
    }
}
```

移过来的 **SignedQuery** 如下

```Java
package com.Bili;

import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;


public final class SignedQuery {

    /* renamed from: c  reason: collision with root package name */
    private static final char[] f14891c = "0123456789ABCDEF".toCharArray();
    public final String a;
    public final String b;

    public SignedQuery(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    private static boolean a(char c2, String str) {
        return (c2 >= 'A' && c2 <= 'Z') || (c2 >= 'a' && c2 <= 'z') || !((c2 < '0' || c2 > '9') && "-_.~".indexOf(c2) == -1 && (str == null || str.indexOf(c2) == -1));
    }

    static String b(String str) {
        return c(str, null);
    }

    static String c(String str, String str2) {
        StringBuilder sb = null;
        if (str == null) {
            return null;
        }
        int length = str.length();
        int i2 = 0;
        while (i2 < length) {
            int i3 = i2;
            while (i3 < length && a(str.charAt(i3), str2)) {
                i3++;
            }
            if (i3 == length) {
                if (i2 == 0) {
                    return str;
                }
                sb.append((CharSequence) str, i2, length);
                return sb.toString();
            }
            if (sb == null) {
                sb = new StringBuilder();
            }
            if (i3 > i2) {
                sb.append((CharSequence) str, i2, i3);
            }
            i2 = i3 + 1;
            while (i2 < length && !a(str.charAt(i2), str2)) {
                i2++;
            }
            try {
                byte[] bytes = str.substring(i3, i2).getBytes("UTF-8");
                int length2 = bytes.length;
                for (int i4 = 0; i4 < length2; i4++) {
                    sb.append('%');
                    sb.append(f14891c[(bytes[i4] & 240) >> 4]);
                    sb.append(f14891c[bytes[i4] & 15]);
                }
            } catch (UnsupportedEncodingException e) {
                throw new AssertionError(e);
            }
        }
        return sb == null ? str : sb.toString();
    }

    static String r(Map<String, String> map) {
        if (!(map instanceof SortedMap)) {
            map = new TreeMap(map);
        }
        StringBuilder sb = new StringBuilder(256);
        for (Map.Entry<String, String> entry : map.entrySet()) {
            String key = entry.getKey();
            if (!key.isEmpty()) {
                sb.append(b(key));
                sb.append(ContainerUtils.KEY_VALUE_DELIMITER);
                String value = entry.getValue();
                sb.append(value == null ? "" : b(value));
                sb.append(ContainerUtils.FIELD_DELIMITER);
            }
        }
        int length = sb.length();
        if (length > 0) {
            sb.deleteCharAt(length - 1);
        }
        if (length == 0) {
            return null;
        }
        return sb.toString();
    }

    public String toString() {
        String str = this.a;
        if (str == null) {
            return "";
        }
        if (this.b == null) {
            return str;
        }
        return this.a + "&sign=" + this.b;
    }
}
```

然后就接着补 JNI 调用

```Java
@Override
public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
    switch (signature){
        case "com/bilibili/nativelibrary/SignedQuery->r(Ljava/util/Map;)Ljava/lang/String;":{
            Map map = (Map) varArg.getObjectArg(0).getValue();
            return new StringObject(vm, SignedQuery.r(map));
        }
    }
    return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
}
```

接着继续运行，报错

```Java
[15:00:04 025]  WARN [com.github.unidbg.AbstractEmulator] (AbstractEmulator:417) - emulate RX@0x120c679b[libc.so]0x1b79b exception sp=unidbg@0xe4fff658, msg=com/bilibili/nativelibrary/SignedQuery-><init>(Ljava/lang/String;Ljava/lang/String;)V, offset=7ms @ Runnable|Function32 address=0x12001c97, arguments=[unidbg@0xfffe12a0, -288775324, 2100961961]
Exception in thread "main" java.lang.NullPointerException: Cannot invoke "com.github.unidbg.linux.android.dvm.DvmObject.getValue()" because the return value of "com.github.unidbg.linux.android.dvm.DvmClass.callStaticJniMethodObject(com.github.unidbg.Emulator, String, Object[])" is null
	at com.test3.TEST3.callS(TEST3.java:69)
	at com.test3.TEST3.main(TEST3.java:51)
```

补环境

```Java
@Override
public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
    switch (signature){
        case "com/bilibili/nativelibrary/SignedQuery-><init>(Ljava/lang/String;Ljava/lang/String;)V":{
            String arg1 = varArg.getObjectArg(0).getValue().toString();
            String arg2 = varArg.getObjectArg(1).getValue().toString();
            return vm.resolveClass("com/bilibili/nativelibrary/SignedQuery").newObject(new SignedQuery(arg1, arg2));
        }
    }
    return super.newObject(vm, dvmClass, signature, varArg);
}
```

补完之后，即可跑通，打印结果

![image-20250713151537052](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250713151537052.png)

```shell
call s result: appkey=1d8b6e7d45233436&build=6180500&channel=shenma069&device=android&mobi_app=android&s_locale=zh_CN&ts=1752390908&sign=2796f4e6df84ead8fe0ff512bee8e24b
```

符合预期

附上完整代码：

```Java
package com.test3;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.*;


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
        String result = test3.callS();
        System.out.println("call s result: " + result);
    }

    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        System.out.println("lilac open: " + pathname);
        return null;
    }

    public String callS(){
        TreeMap<String, String> map = new TreeMap<>();
        map.put("build", "6180500");
        map.put("mobi_app", "android");
        map.put("channel", "shenma069");
        map.put("appkey", "1d8b6e7d45233436");
        map.put("s_locale", "zh_CN");
        map.put("device", "android");
        DvmObject<?> mapObject = ProxyDvmObject.createObject(vm, map);
        String result = LibBili.callStaticJniMethodObject(emulator, "s(Ljava/util/SortedMap;)Lcom/bilibili/nativelibrary/SignedQuery;", mapObject).getValue().toString();
        return result;
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature){
            case "java/util/Map->isEmpty()Z":{
                Map map = (Map) dvmObject.getValue();
                return map.isEmpty();
            }
        }
        return super.callBooleanMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature){
            case "java/util/Map->get(Ljava/lang/Object;)Ljava/lang/Object;":{
                Map map = (Map) dvmObject.getValue();
                // 不要忘了getvalue
                Object key = varArg.getObjectArg(0).getValue();
                return ProxyDvmObject.createObject(vm, map.get(key));
            }
            case "java/util/Map->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;":{
                Map map = (Map) dvmObject.getValue();
                Object key = varArg.getObjectArg(0).getValue();
                Object value = varArg.getObjectArg(1).getValue();
                return ProxyDvmObject.createObject(vm, map.put(key, value));
            }
        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature){
            case "com/bilibili/nativelibrary/SignedQuery->r(Ljava/util/Map;)Ljava/lang/String;":{
                Map map = (Map) varArg.getObjectArg(0).getValue();
                return new StringObject(vm, SignedQuery.r(map));
            }
        }
        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature){
            case "com/bilibili/nativelibrary/SignedQuery-><init>(Ljava/lang/String;Ljava/lang/String;)V":{
                String arg1 = varArg.getObjectArg(0).getValue().toString();
                String arg2 = varArg.getObjectArg(1).getValue().toString();
                return vm.resolveClass("com/bilibili/nativelibrary/SignedQuery").newObject(new SignedQuery(arg1, arg2));
            }
        }
        return super.newObject(vm, dvmClass, signature, varArg);
    }




    private static final char[] f14892c = "0123456789ABCDEF".toCharArray();
    public static final class SignedQuery {

        public final String a;
        public final String b;

        public SignedQuery(String str, String str2) {
            this.a = str;
            this.b = str2;
        }

        private static boolean a(char c2, String str) {
            return (c2 >= 'A' && c2 <= 'Z') || (c2 >= 'a' && c2 <= 'z') || !((c2 < '0' || c2 > '9') && "-_.~".indexOf(c2) == -1 && (str == null || str.indexOf(c2) == -1));
        }

        static String b(String str) {
            return c(str, null);
        }

        static String c(String str, String str2) {
            StringBuilder sb = null;
            if (str == null) {
                return null;
            }
            int length = str.length();
            int i2 = 0;
            while (i2 < length) {
                int i3 = i2;
                while (i3 < length && a(str.charAt(i3), str2)) {
                    i3++;
                }
                if (i3 == length) {
                    if (i2 == 0) {
                        return str;
                    }
                    sb.append((CharSequence) str, i2, length);
                    return sb.toString();
                }
                if (sb == null) {
                    sb = new StringBuilder();
                }
                if (i3 > i2) {
                    sb.append((CharSequence) str, i2, i3);
                }
                i2 = i3 + 1;
                while (i2 < length && !a(str.charAt(i2), str2)) {
                    i2++;
                }
                try {
                    byte[] bytes = str.substring(i3, i2).getBytes("UTF-8");
                    int length2 = bytes.length;
                    for (int i4 = 0; i4 < length2; i4++) {
                        sb.append('%');
                        sb.append(f14892c[(bytes[i4] & 240) >> 4]);
                        sb.append(f14892c[bytes[i4] & 15]);
                    }
                } catch (UnsupportedEncodingException e) {
                    throw new AssertionError(e);
                }
            }
            return sb == null ? str : sb.toString();
        }

        static String r(Map<String, String> map) {
            if (!(map instanceof SortedMap)) {
                map = new TreeMap(map);
            }
            StringBuilder sb = new StringBuilder(256);
            for (Map.Entry<String, String> entry : map.entrySet()) {
                String key = entry.getKey();
                if (!key.isEmpty()) {
                    sb.append(b(key));
                    sb.append(ContainerUtils.KEY_VALUE_DELIMITER);
                    String value = entry.getValue();
                    sb.append(value == null ? "" : b(value));
                    sb.append(ContainerUtils.FIELD_DELIMITER);
                }
            }
            int length = sb.length();
            if (length > 0) {
                sb.deleteCharAt(length - 1);
            }
            if (length == 0) {
                return null;
            }
            return sb.toString();
        }

        public String toString() {
            String str = this.a;
            if (str == null) {
                return "";
            }
            if (this.b == null) {
                return str;
            }
            return this.a + "&sign=" + this.b;
        }
    }


    public static class ContainerUtils {
        public static final String FIELD_DELIMITER = "&";
        public static final String KEY_VALUE_DELIMITER = "=";

        public static <K, V> boolean equals(Map<K, V> map, Map<K, V> map2) {
            if (map == map2) {
                return true;
            }
            boolean z = false;
            if (map == null || map2 == null || map.size() != map2.size()) {
                return false;
            }
            Iterator<Map.Entry<K, V>> it = map.entrySet().iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                Map.Entry<K, V> next = it.next();
                if (map2.get(next.getKey()) != next.getValue()) {
                    z = true;
                    break;
                }
            }
            return !z;
        }

        public static <K, V> int hashCode(Map<K, V> map) {
            return toString(map).hashCode();
        }

        public static <K> String toString(List<K> list) {
            if (list == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            int i2 = 0;
            for (K k : list) {
                int i3 = i2 + 1;
                if (i2 > 0) {
                    sb.append(FIELD_DELIMITER);
                }
                sb.append(k.toString());
                i2 = i3;
            }
            return sb.toString();
        }

        public static <K, V> String toString(Map<K, V> map) {
            if (map == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            int i2 = 0;
            for (Map.Entry<K, V> entry : map.entrySet()) {
                int i3 = i2 + 1;
                if (i2 > 0) {
                    sb.append(FIELD_DELIMITER);
                }
                sb.append(entry.getKey().toString());
                sb.append(KEY_VALUE_DELIMITER);
                sb.append(entry.getValue().toString());
                i2 = i3;
            }
            return sb.toString();
        }

        public static <K> String toString(Set<K> set) {
            if (set == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            int i2 = 0;
            for (K k : set) {
                int i3 = i2 + 1;
                if (i2 > 0) {
                    sb.append(FIELD_DELIMITER);
                }
                sb.append(k.toString());
                i2 = i3;
            }
            return sb.toString();
        }
    }


}
```



### 六、参考

[Unidbg 的基本使用（四）](https://www.yuque.com/lilac-2hqvv/xdwlsg/uo6guvore38kr29y?# 《Unidbg 的基本使用（四）》)
