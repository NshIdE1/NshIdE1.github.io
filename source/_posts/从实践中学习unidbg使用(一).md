---
title: 从实践中学习unidbg使用(一)
tags: [Unidbg]
categories: Unidbg学习
---

# 从实践中学习unidbg使用(一)

### 一、引言

目标APK：lvzhou.apk

目标方法声明处的Dex：target.dex。样本APK在Java层做了加壳(360加固)，所以建议直接使用附件中的target.dex，或使用其他工具进行脱壳(frida-dump即可)

目标方法实现：liboasiscore.so

### 二、任务描述

首先先反编译target.dex，但使用jadx反编译时报错，于是就使用了GDA进行反编译，找到NativeApi类，其中s方法就是本篇的目标。

```Java
package com.weibo.xvideo.NativeApi;
import java.lang.Object;
import java.lang.String;
import java.lang.System;

public final class NativeApi	// class@0011ea from target.dex
{

    public void NativeApi(){
       super();
       System.loadLibrary("oasiscore");
    }
    public native final String d(String p0);
    public native final String dg(String p0,boolean p1);
    public native final String e(String p0);
    public native final String s(byte[] p0,boolean p1);
}
```

然后写个Frida脚本hook一下，就先针对样本APK在运行时该方法传入的值和返回值进行分析。

```js
setTimeout(function() {
    Java.perform(function() {
        let NativeApi = Java.use("com.weibo.xvideo.NativeApi");
        NativeApi["s"].implementation = function (bArr, z) {
            console.log('s is called' + ', ' + 'bArr: ' + bArr + ", " + "z: " + z);
            let ret = this.s(bArr, z);
            console.log('s ret value is ' + ret);
            return ret;
        };
    });
}, 5000);
```

这里需要注意的一个点就是因为这个APK加壳了，所以导致如果在指令中直接写

```bash
frida -U -f "com.weibo.xvideo" -l hook.js
```

会报错显示找不到进程，用以下指令

```bash
frida -U -f "com.sina.oasis" -l hook.js
```

就会接收到以下信息
![](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250528173853560.png)

把bArr转成ASCII码就是

> aid=01A1H7Fp6UDqucgEerCNxpT41YVcU_j_LzwYFOs_L2l3_OoL8.&cfrom=28B5295010&cuid=0&noncestr=d101Ed45892MF20mM2LJ54i62EhwO3&phone=17816087093&platform=ANDROID&timestamp=1748421079454&ua=Google-Pixel3_oasis_3.5.8_Android__Android12&version=3.5.8&vid=2020786998479&wm=20004_90024
>
> s ret value is 08e2a22b03840858f5e78858e4575db2

就是程序发出的一个URL请求参数字符串，通常用于身份验证、用户追踪、设备标识、版本控制等。然后我们拿到传入的参数，接下来主动调用**s**方法

```Java
setTimeout(function () {
  Java.perform(function () {
    function stringToBytes(str) {
      var javaString = Java.use("java.lang.String");
      return javaString.$new(str).getBytes();
    }

    let NativeApi = Java.use("com.weibo.xvideo.NativeApi");
    let arg1 =     "aid=01A1H7Fp6UDqucgEerCNxpT41YVcU_j_LzwYFOs_L2l3_OoL8.&cfrom=28B5295010&cuid=0&noncestr=d101Ed45892MF20mM2LJ54i62EhwO3&phone=17816087093&platform=ANDROID&timestamp=1748421079454&ua=Google-Pixel3_oasis_3.5.8_Android__Android12&version=3.5.8&vid=2020786998479&wm=20004_90024";
    let arg2 = false;
    let ret = NativeApi.$new().s(stringToBytes(arg1), arg2);
    console.log("ret:" + ret);
  });
}, 5000);
```

得到返回值是

> ret:1e3780f50056a3fea76b35592bfc3efc

接下来我们开始使用unidbg，本篇的目的就是使用unidbg复现对s方法的调用，并得到Frida主动调用一致的结果。

### 三、初始化

在test/java路径下新建包和对应的类，包名，类名根据自己喜欢来就好

```Java
package com.test0;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.nio.charset.StandardCharsets;

//继承AbstractJni类之后，TEST0类就可以接收和响应Dalvik VM里本地方法调用，同时可以自定义JNI行为
public class TEST0 extends AbstractJni {
    private final AndroidEmulator emulator;
    private final DvmClass NativeApi;
    private final VM vm;

    public TEST0() {
        //模拟器初始化
        emulator = AndroidEmulatorBuilder
                //设置架构，执行速度ARM64相比ARM32会快一些，10%上下；而Unidbg对ARM32的支持和完善程度高于ARM64
                .for64Bit()
                //告诉unidbg使用Unicorn模拟器来执行指令
                .addBackendFactory(new Unicorn2Factory(true))
                //这个参数是用来设置进程名的，这个很重要，并且填写的是样本APK真实进程名，否则会带来隐患。若为空，一般Unidbg
                //会将"unidbg"作为进程名返回。
                .setProcessName("com.sina.oasis")
                .build();

//        //是否开启多线程
//        //设置执行多少条指令切换一次线程
//        emulator.getBackend().registerEmuCountHook(10000);
//        //开启线程调度器
//        emulator.getSyscallHandler().setEnableThreadDispatcher(true);

        //获取模拟器的内存实例，也就是模拟器的内存操作接口
        Memory memory = emulator.getMemory();
        //创建一个库解析器，并设置Android版本为23(Android 6.0)
        memory.setLibraryResolver(new AndroidResolver(23));
        //创建虚拟机并指定apk文件
        vm = emulator.createDalvikVM(new File("D:\\Compilation_Enviroment\\unidbg-master\\unidbg-android\\src\\test\\java\\com\\test0\\lvzhou.apk"));
        //设置当前类为虚拟机的JNI接口实现，即告诉虚拟机，如果 native 层调用 Java 方法、访问 Java 字段，使用我（这个类）来处理。
        vm.setJni(this);
        //打开 unidbg 的详细日志输出（verbose mode）
        vm.setVerbose(true);
        //加载so模块
        DalvikModule dm = vm.loadLibrary("oasiscore", true);
        //加载目标类
        NativeApi = vm.resolveClass("com/weibo/xvideo/NativeApi");
        dm.callJNI_OnLoad(emulator);
    }

    public String calls() {
        String arg1 = "aid=01A1H7Fp6UDqucgEerCNxpT41YVcU_j_LzwYFOs_L2l3_OoL8.&cfrom=28B5295010&cuid=0&" +
                "noncestr=d101Ed45892MF20mM2LJ54i62EhwO3&phone=17816087093&platform=ANDROID&" +
                "timestamp=1748421079454&ua=Google-Pixel3_oasis_3.5.8_Android__Android12&version=3.5.8&" +
                "vid=2020786998479&wm=20004_90024";
        Boolean arg2 = false;
        String ret = NativeApi.newObject(null).callJniMethodObject(emulator, "s([BZ)Ljava/lang/String;", arg1.getBytes(StandardCharsets.UTF_8), arg2).getValue().toString();
        return ret;
    }

    public static void main(String[] args) {
        TEST0 test0 = new TEST0();
        String result = test0.calls();
        System.out.println("Call s result:\n" + result);
    }

}
```

每行代码的含义都已注释好。
总的来说，就是进行了初始化模拟器、初始化内存、设置依赖库路径、创建虚拟机处理器、加载目标so、执行其JNI_Onload函数这一系列操作。

运行后得到我们的预期结果

> Call s result:
> 1e3780f50056a3fea76b35592bfc3efc

### 四、解释

回顾DEX的反编译结果

```Java
package com.weibo.xvideo.NativeApi;
import java.lang.Object;
import java.lang.String;
import java.lang.System;

public final class NativeApi	// class@0011ea from target.dex
{

    public void NativeApi(){
       super();
       System.loadLibrary("oasiscore");
    }
    public native final String d(String p0);
    public native final String dg(String p0,boolean p1);
    public native final String e(String p0);
    public native final String s(byte[] p0,boolean p1);
}
```

s方法是NativeApi类里的实例方法，因此在调用它时，需要先获取NativeApi类，再创建它的实例，最后才是发起调用，比如 Frida Call 代码就遵循这样的原则。Java.use获取类对象，$new()实例化，然后调用s方法。

Unidbg 作为 SO 模拟器，它没有加载 DEX，更没有运行 DEX，自然没法获取其中对应的类信息，那么它如何处理NativeApi以及更多的用户自定义的类库访问需求？这是 Unidbg 的核心问题之一。

首先，它构建了一套描述类库，或者说映射类库的机制。在 JAVA 层，一个类是Class，在 JNI 层，一个类是Jclass，而在 Unidbg 的 JNI 层，一个类是DvmClass。

在 Unidbg 中，通过vm.resolveClass(className)可以声明一个类名是className的DvmClass。

```Java
DvmClass NativeApi = vm.resolveClass("com/weibo/xvideo/NativeApi");
```

在类名的表述上，必须是全类名，旧版 Unidbg 上必须用斜杠/作为分隔符，而 Unidbg 0.9.6 及以上的当前版本中，用斜杠/或点号.分割都可行，因为resolveClass会替我们做这种替换。

resolveClass是一个可变参数方法，它的第二个参数是可变参数，用于进一步描述我们所构造的这个DvmClass的父类和接口。

举个例子，Android 的 Application 类

![image-20250528184922392](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250528184922392.png)

它继承自 ContextWrapper，ContextWrapper 继承自 Context，下面的图看起来更清晰。

![image-20250528184938746](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250528184938746.png)

如果想用DvmClass表明 Application 的父类情况，可以像下面这样嵌套表示。

```Java
DvmClass Context = vm.resolveClass("android/content/Context");
DvmClass ContextWrapper = vm.resolveClass("android/content/ContextWrapper", Context);
DvmClass Application = vm.resolveClass("android/app/Application", ContextWrapper);
```

需要注意，这并不意味着我们必须非要这样才能表示 Application 类，类是数据和方法的集合，DvmClass并不是要完美模拟对应的类，更多时候只是简单的“占位”，使之符合形式上的要求。

接下来讨论类的实例化，对类调用newObject(Object value)即可完成实例化，得到一个形式上的对象。

```Java
DvmClass NativeApi = vm.resolveClass("com/weibo/xvideo/NativeApi");
DvmObject<?> nativeApi = NativeApi.newObject(null); 
```

在 Java 中它是 Object，JNI 中叫做 Jobject，Unidbg 里叫 DvmObject。

newObject 方法的参数和真实对象的构造函数的参数不是一回事，它只是一种“形式上”的对象，不需要和真实的对象保持一致。

resolveClass以及newObject只是对真实类和对象的描述、占位、投影，然后根据程序逻辑上对这些类、对象的使用情况，再逐步完善这样的一种描述、占位、投影，使之能完成基本需求。

这么做是有好处的，我们常说“吃多少，拿多少”，Unidbg 所设计的这种逻辑，就是程序用多少，就补多少。一个对象可能有一百个方法，两百个成员属性，但程序中如果只使用到了其中的一个方法，两个属性，那么只需要处理它们，而不用管其他的部分。

通过NativeApi.newObject(null)创建实例后，接下来就是发起函数调用。

接下里是关于**发起调用**的一些解释

我们想对`s`发起调用，因为它的返回值是字符串，是对象，所以用callJniMethodObject，如果返回值是 int 就用callJniMethodInt，其他可选方法如下。

![image-20250528185245790](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250528185245790.png)

如果s是静态方法，那么自然不需要 newObject，调用则通过 callStaticJNIMethodXXX 系列函数。

![image-20250528185359630](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250528185359630.png)

接下来看看方法的具体参数，参数 1 是模拟器实例，参数 2 是方法签名，接着是可变参数，用于传入调用方法的参数。

```JAVA
String arg1 = "aid=aid=01A1H7Fp6UDqucgEerCNxpT41YVcU_j_LzwYFOs_L2l3_OoL8.&cfrom=28B5295010&cuid=0&noncestr=d101Ed45892MF20mM2LJ54i62EhwO3&phone=17816087093&platform=ANDROID&timestamp=1748421079454&ua=Google-Pixel3__oasis__3.5.8__Android__Android12&version=3.5.8&vid=2020786998479&wm=20004_90024";
Boolean arg2 = false;
String ret = NativeApi.newObject(null).callJniMethodObject(emulator, "s([BZ)Ljava/lang/String;", arg1.getBytes(StandardCharsets.UTF_8), arg2).getValue().toString();
```

这里方法签名填入了s([BZ)Ljava/lang/String;，直接填入s会报错，提示无法找到方法。

函数名 + 参数类型 + 返回值类型

```Java
public final native String s(@NotNull byte[] bArr, boolean z);
```

我们可以手动转写，大家在学习 Smali 以及 JNI 时应该都和这种表示方法打过交道。

| Java类型 | 签名    |
| -------- | ------- |
| boolean  | Z       |
| byte     | B       |
| char     | C       |
| short    | S       |
| int      | I       |
| long     | J       |
| float    | F       |
| double   | D       |
| void     | V       |
| class    | Lclass; |
| [ type   | type[]  |

对于基础类型，除了 boolean 都通用首字母大写表示，boolean 和 byte 的首字母重复，所以由 byte 用 B 首字母，boolean 用 Z 形成区分。

对于对象类型，则是 L 开头，分号结尾，中间跟着方法全类名，以斜杠/分割。

参数签名就是将参数和返回值转换成这个格式，然后直接拼接起来。

- byte[] bArr即 [B
- boolean z即 Z
- 返回值String，即Ljava/lang/String;。

拼接在一起就是s([BZ)Ljava/lang/String;，手写多少有点麻烦，而且容易出错，在更多时候我们会通过其他方式处理。

如果目标函数采用动态绑定，那么在 Undibg 的 JNI_OnLoad 执行流中找到RegisterNative日志即可看到对应的方法签名。

```shell
RegisterNative(com/weibo/xvideo/NativeApi, s([BZ)Ljava/lang/String;, RX@0x400116cc[liboasiscore.so]0x116cc)
RegisterNative(com/weibo/xvideo/NativeApi, e(Ljava/lang/String;)Ljava/lang/String;, RX@0x40011af4[liboasiscore.so]0x11af4)
RegisterNative(com/weibo/xvideo/NativeApi, d(Ljava/lang/String;)Ljava/lang/String;, RX@0x40011cd8[liboasiscore.so]0x11cd8)
RegisterNative(com/weibo/xvideo/NativeApi, dg(Ljava/lang/String;Z)Ljava/lang/String;, RX@0x4001220c[liboasiscore.so]0x1220c)
```

如果目标函数采用静态绑定，那么直接用传入`s`即可，不需要写s([BZ)Ljava/lang/String;。

除了这个办法外，也可以将 JADX 中切换到 Smali 展示模式，找到对应方法即可看到方法签名。

然后是**参数的传递**

回到调用代码，在 Unidbg 中如何传递函数的入参？

```Java
public String calls(){
    String arg1 = "aid=01A-khBWIm48A079Pz_DMW6PyZR8uyTumcCNm4e8awxyC2ANU.&cfrom=28B5295010&cuid=5999578300&noncestr=46274W9279Hr1X49A5X058z7ZVz024&platform=ANDROID&timestamp=1621437643609&ua=Xiaomi-MIX2S__oasis__3.5.8__Android__Android10&version=3.5.8&vid=1019013594003&wm=20004_90024";
    Boolean arg2 = false;
    String ret = NativeApi.newObject(null).callJniMethodObject(emulator, "s([BZ)Ljava/lang/String;", arg1.getBytes(StandardCharsets.UTF_8), arg2).getValue().toString();
    return ret;
}
```

参数 1 是字符串，参数 2 是布尔值，直接传递即可，不需要做其他处理，两大类参数都可以直接传递。

- 基本类型直接传递，int、long、boolean、double 等。
- 下面几种对象类型也可以直接传递

- String
- byte 数组
- short 数组
- int 数组
- float 数组
- double 数组
- Enum 枚举类型

除此之外还有许多种可能的参数，比如字符串数组、二维数组、Android Context/Application、HashMap 等等，在大体上遵循两类处理办法。

1. 如果是 JDK 中包含的类库和方法，比如二维数组、字符串数组、HashMap 等等，直接构造后使用ProxyDvmObject.createObject(vm, obj);构造出对象。除此之外比如 Okhttp3 之类的第三方类库，导入到本地环境里，也可以使用这个办法。
2. 如果是 JDK 中无法包含的类库，比如 Android FrameWork 以及样本自定义的类库，通过resolveClass(className).newObject处理，就像本节的NativeApi那样处理。



# 参考

[Unidbg 的基本使用（一）](https://www.yuque.com/lilac-2hqvv/xdwlsg/gmbn45b5n6g59kks#I0Nu4)