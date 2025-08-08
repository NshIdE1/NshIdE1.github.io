---
title: Frida入门
tags: [Android, Frida]
categories: Frida入门
---

# Frida入门

##### 一.Frida的相关链接

1.Frida server下载：[Releases · frida/frida (github.com)](https://github.com/frida/frida/releases?page=2)

2.Frida例题：[DERE-ad2001/Frida-Labs: The repo contains a series of challenges for learning Frida for Android Exploitation. (github.com)](https://github.com/DERE-ad2001/Frida-Labs)

**相关指令：**

1.adb version ：显示 adb 版本

2.adb help：帮助信息，查看adb所支持的所有命令

3.adb devices：查看当前连接的设备，已连接的设备会显示出来

4.adb get-serialno：也可以查看设备号

5.adb root：获取Android管理员（root用户）的权限

6.adb shell：登录设备 shell，该命令将登录设备的shell（内核），登录shell后，可以使用 cd，ls，rm 等Linux命令

7.adb -d：如果同时连了usb，又开了模拟器，连接当前唯一通过usb连接的安卓设备

8.adb -e shell：指定当前连接此电脑的唯一的一个模拟器

9.adb -s <设备号> shell：当电脑插多台手机或模拟器时，指定一个设备号进行连接

10.exit：退出

11.adb kill-server：杀死当前adb服务，如果连不上设备时，杀掉重启。（没事不要用它）

12.adb start-server：杀掉后重启

13.adb shell pm list packages：列出当前设备/手机，所有的包名

14.adb shell pm list packages -f：显示包和包相关联的文件(安装路径)

15.adb shell pm list packages -d：显示禁用的包名
16.adb shell pm list packages -e：显示当前启用的包名
17.adb shell pm list packages -s：显示系统应用包名
18.adb shell pm list packages -3：显示已安装第三方的包名
19.adb shell pm list packages xxxx：加需要过滤的包名，如：xxx = taobao
20.adb install <文件路径\apk>：将本地的apk软件安装到设备(手机)上。如手机外部安装需要密码，        记得手机输入密码。   

21.adb install -r <文件路径\apk>：覆盖安装

22.adb install -d <文件路径\apk>：允许降级覆盖安装
23.adb install -g <文件路径\apk>：授权/获取权限，安装软件时把所有权限都打开
24.adb uninstall <包名>：卸载该软件/app。
      注意：安装时安装的是apk，卸载时是包名，可以通过 adb shell pm list packages 查看需要卸载的包名。
25.adb shell pm uninstall -k <包名>：虽然把此应用卸载，但仍保存此应用的数据和缓存  
26.adb shell am force-stop <包名>：强制退出该应用/app

27.adb push <本地路径\文件或文件夹> <手机端路径>：把本地(pc机)的文件或文件夹复制到设备(手 机)

注意点1：pc机路径与Android机路径，分隔符是不同的。

注意点2：复制失败，大概率是无权限。可先使用上面介绍过的两个命令：adb root；adb remount。在使用 adb push 命令

**adb pull <手机端路径/文件或文件夹> <pc机路径>：把设备(手机)的文件或文件夹复制到本地。**注意点同上

28.更多：

adb shell logcat -c：清理现有日志
adb shell logcat -v time ：输出日志，信息输出在控制台
adb shell logcat -v time > <存放路径\log.txt>：输出日志并保存在本地文件
Ctrl+C：终止日志抓取
adb shell logcat -v time *:E > <存放路径\log.txt>：打印级别为Error的信息
日志的等级：
-v：Verbse（明细）
-d：Debug（调试）
-i：Info（信息）
-w：Warn（警告）
-e：Error（错误）
-f：Fatal（严重错误）
抓取日志的步骤先输入命令启动日志，然后操作 App，复现 bug，再 ctrl+c 停止日志，分析本地保存的文件。
：日志是记录手机系统在运行app时有什么异常的事件
EXCEPTION
也可以把更详细得Anr日志拉取出来：adb shell pull /data/anr/traces.txt <存放路径>

**adb shell getprop ro.product.model：获取设备型号**

**adb shell getprop ro.build.version.release：获取Android系统版本**

**adb get-serialno：获取设备的序列号（设备号）**

**adb shell wm size：获取设备屏幕分辨率**

**adb shell screencap -p /sdcard/mms.png：屏幕截图  
adb shell screencap -p /sdcard/screenshot.png：屏幕截图**

**adb pull /sdcard/mms.png <存放的路径>：将截图导出到本地  
adb pull /sdcard/screenshot.png <存放的路径>：将截图导出到本地**

**adb shell dumpsys activity |find “mResumedActivity”：查看前台应用包名，必须先启动app，适用于Android 8.0以上**

**adb shell cat /proc/meminfo：获取手机内存信息**

**adb shell df：获取手机存储信息**

**adb shell screenrecord <存放路径/xxx.mp4>：录屏，命名以.mp4结尾  
adb shell screenrecord --time-limit 10 <存放路径/xxx.mp4>：录屏时间为10秒**

------------------------------------------------------------------------------------------------------------------------------------

##### 二.安卓脱壳--Xposed&反射大师

例题：[XYCTF]Trust me

**1.分辨是否加壳**

用jadx打开，![f2f181ff-9b1d-4381-a3a2-51da7e72f5cd](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/f2f181ff-9b1d-4381-a3a2-51da7e72f5cd.png)

![08d77483-4d7f-4a79-a46e-1997406c9bfe](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/08d77483-4d7f-4a79-a46e-1997406c9bfe.png)

可以看到两个包名不是同一个，也就是说真正的程序入口和jadx反编译出来的不一样，说明可能加壳了，同时还有不少安卓第一代壳的特征，

![498ee0a5-3841-49b5-a312-8a6f78c4f076](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/498ee0a5-3841-49b5-a312-8a6f78c4f076.png)

![a3010d65-ac47-4c92-87b6-064828defcdd](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/a3010d65-ac47-4c92-87b6-064828defcdd.png)

那么这里我们可以用Xposed&反射大师来脱壳，具体安装这里不做过多说明，网上有。我这里用的**夜神模拟器**，**Xposed**，**反射大师**。

在模拟器上打开反射大师，点击我们需要脱壳的app，然后点击选择这个软件

![01eaa759-4c60-4920-ad43-1e90d3529783](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/01eaa759-4c60-4920-ad43-1e90d3529783.png)

然后点击，打开

![39db2c26-8297-44b2-ba57-93c9b812cffc](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/39db2c26-8297-44b2-ba57-93c9b812cffc.png)

可以看到软件页面中心有个红色六芒星

![44a5cd61-c8ac-45e7-b856-b2f1b4feaecc](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/44a5cd61-c8ac-45e7-b856-b2f1b4feaecc.png)

点击六芒星，可以看到

![a45c7382-94f6-4784-a3f7-f8651b42e3d7](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/a45c7382-94f6-4784-a3f7-f8651b42e3d7.png)

再点击当前ACTIVITY

![205988b5-9415-4caa-9415-5175e8d3e1f4](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/205988b5-9415-4caa-9415-5175e8d3e1f4.png)

长按写出DEX，

![bbaf31a4-2198-42ec-b173-0b2a96e86b7a](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/bbaf31a4-2198-42ec-b173-0b2a96e86b7a.png)

点击确定，

![aca4393d-5e0b-4b33-9f8c-8da436036d8d](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/aca4393d-5e0b-4b33-9f8c-8da436036d8d.png)

然后点击复制，方便后续pull

![8d8a410d-8a05-4314-ad89-cb4492500104](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/8d8a410d-8a05-4314-ad89-cb4492500104.png)

这里pull出来的文件就是在我们cmd的路径，文件名就叫dump

![379bc70f-d5e5-4841-9100-5c2b865bfc85](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/379bc70f-d5e5-4841-9100-5c2b865bfc85.png)

里面的class.dex就是dump下来的文件，用jadx就可以继续分析了。

![0d64aed0-449e-436a-a3c2-7426b63cc7a9](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/0d64aed0-449e-436a-a3c2-7426b63cc7a9.png)

这就是真正正确的app入口，函数整体逻辑就是对数据库的加密，可以用spl注入的万能钥匙，直接秒了，或者就是正在逆向分析，可以找到数据文件，进行异或，![3a0e97a5-4d3b-4219-a08d-017b117c9e87](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/3a0e97a5-4d3b-4219-a08d-017b117c9e87.png)

就是异或0xFF，这里这个数据库不能用jadx打开，会卡死，可以改文件后缀名，然后找到文件，用010editor打开，进行异或，就可以找到flag。

------------------------------------------------------------------------------------------------------------------------------------





##### 三.Frida 用法（1）.js脚本hook一个方法

1.工具：1.jadx----用于进行静态分析，也可以进行动态调试（JEB似乎更好）。 

雷神模拟器 9（Android 9）----原本自带的adb.exe好像有问题，建议另行自找。（需要root）

Frida   Frida server

例题：Frida 0x1



2.拿到附件，一个.apk文件，我们可以先用MT管理器看看APP入口<img src="https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1721640027318.png" title="" alt="1721640027318" data-align="left">

找到了之后，就可以用jadx打开，先静态分析看看逻辑

```java
package com.ad2001.frida0x1;

import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import java.util.Random;

/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        final EditText editText = (EditText) findViewById(R.id.editTextTextPassword);
        this.t1 = (TextView) findViewById(R.id.textview1);
        final int i = get_random();
        ((Button) findViewById(R.id.button)).setOnClickListener(new View.OnClickListener() { // from class: com.ad2001.frida0x1.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                String obj = editText.getText().toString();
                if (TextUtils.isDigitsOnly(obj)) {
                    MainActivity.this.check(i, Integer.parseInt(obj));
                } else {
                    Toast.makeText(MainActivity.this.getApplicationContext(), "Enter a valid number !!", 1).show();
                }
            }
        });
    }

    int get_random() {
        return new Random().nextInt(100);
    }

    void check(int i, int i2) {
        if ((i * 2) + 4 == i2) {
            Toast.makeText(getApplicationContext(), "Yey you guessed it right", 1).show();
            StringBuilder sb = new StringBuilder();
            for (int i3 = 0; i3 < 20; i3++) {
                char charAt = "AMDYV{WVWT_CJJF_0s1}".charAt(i3);
                if (charAt < 'a' || charAt > 'z') {
                    if (charAt >= 'A') {
                        if (charAt <= 'Z') {
                            charAt = (char) (charAt - 21);
                            if (charAt >= 'A') {
                            }
                            charAt = (char) (charAt + 26);
                        }
                    }
                    sb.append(charAt);
                } else {
                    charAt = (char) (charAt - 21);
                    if (charAt >= 'a') {
                        sb.append(charAt);
                    }
                    charAt = (char) (charAt + 26);
                    sb.append(charAt);
                }
            }
            this.t1.setText(sb.toString());
            return;
        }
        Toast.makeText(getApplicationContext(), "Try again", 1).show();
    }
}
```

​        可以看到，APP中位于**com.ad2001.frida0x1**包**MainActivity**类的onCreate方法在程序初始化时会调用get_random()**方法生成一个介于0到100之间的随机数并赋值给变量i。同时，监听**button**的点击，当按下按钮后，程序首先判断输入的内容是不是数字，如果是数字就将其从string转化为int，并将该整数与生成的随机数一起传递给**check**方法。接下来，继续分析**check**方法实现了哪些功能。 

​         **check**方法被传入了两个参数，一个是我们在APP页面输入后提交的的数字i2，一个是程序启动时调用get_random方法生成的**随机数**i。该方法会检查表达式**(i * 2) + 4 == i2)**是否成立，如果成立则将正确的flag输出到绑定的textView控件上，反之则会提示“Try again”。 

​        当然，这个题其实是可以直接逆的，写脚本爆破，但是为了学习frida的用法，我们使用frida来hook出每次程序运行时所生成的随机数i是多少，然后我们再将正确答案输入，便可得到正确flag。

​         PS：因为使用frida进行hook，也是属于动态调.apk文件，所以我们得在aok文件的AndroidMainfestxml清单里查看application中是否有可调式的属性，如果没有得自行加入。<img src="https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1721640598097.png" title="" alt="1721640598097" data-align="left">

然后就可以开始使用frida进行hook了。

3.具体操作

首先先查看adb的连接是否有问题，在终端输入**adb devices**<img src="https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1721640935229.png" title="" alt="1721640935229" data-align="left">

然后输入**adb shell**进入手机，接着输入**su**进入超级管理，再输入**cd /data/local/tmp**进入相应目录（网上大部分都是将frida server存入此文件夹。（**注**：frida和frida server版本需一致，同时frida server的类型需与虚拟机（手机）的架构一直，可用指令**adb shell getprop ro.product.cpu.abi**查看具体信息）。进入目录之后，可以看看文件夹里是否有frida server这个文件，<img src="https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1721641241680.png" title="" alt="1721641241680" data-align="left">

然后修改文件权限**chmod 755 frida-server-16.2\ .1-android-x86_64**，紧接着就可以运行了。然后，我另外再打开一个终端窗口，分别输入![1721641449576](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1721641449576.png)

**adb forward tcp:27042 tcp:27042**
**adb forward tcp:27043 tcp:27043**  进行端口转发监听

最后输入**frida-ps -U**或者**frida-ps -R**看看能否成功输出进程列表，检查frida能否正常使用，![1721641646506](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1721641646506.png)

我们还需编写脚本

```javascript
// 使用Java.perform函数创建一个特殊的Java上下文，用于执行挂钩和Java类操作
Java.perform(function() {                                               
    // 获取应用程序中com.ad2001.frida0x1.MainActivity类的引用
    var MainActivity = Java.use("com.ad2001.frida0x1.MainActivity");

    // 重写MainActivity类的get_random方法的实现
    MainActivity.get_random.implementation = function() {
        // 当get_random方法被调用时，输出一条日志信息
        console.log("MainActivity.get_random is called");

        // 调用原始的get_random方法并获取其返回值
        var ret_val = this.get_random();                                

        // 输出get_random方法的返回结果
        console.log("MainActivity.get_random result is " + ret_val);

        // 返回原始方法的返回值
        return ret_val;
    };
});

```

保存好，然后我们使用**frida -U -f com.ad2001.frida0x1 -l test.js**(test.js是脚本的绝对路径)![1721642126293](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1721642126293.png)

再在jadx中点击运行，就可以看到输出了此次app运行时生成的随机数是多少，再计算 (74 * 2) + 4 = 152，输入，就可得到flag

![1721642239103](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1721642239103.png)

这就是利用frida hook一个方法的完整过程。

对应附件：Frida 0X1_1.apk



**总结**：Frida Hook方法的脚本模板：

```js
Java.perform(function() { 

var <class_reference> = Java.use(“<package_name>.<class>”); 

<class_reference>.<method_to_hook>.implementation = function(<args>) { 

     /* 

       我们自己的方法实现 

     */ 

   }
}
```





------------------------------------------------------------------------------------------------------------------------------------------

##### 四.Frida 用法（2） .js脚本hook一个静态方法

1.工具：还是那几样东西。

2.例题：Frida 0x2

3.分析：

拿到附件apk文件，先安装到雷电9里运行一下，

没有输入，就是很直白，hook。那么接下来我们用jadx反编译为java看看静态逻辑。

```java
package com.ad2001.frida0x2;

import android.os.Bundle;
import android.util.Base64;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: classes3.dex */
public class MainActivity extends AppCompatActivity {
    static TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        t1 = (TextView) findViewById(R.id.textview);
    }

    public static void get_flag(int a) {
        if (a == 4919) {
            try {
                SecretKeySpec secretKeySpec = new SecretKeySpec("HILLBILLWILLBINN".getBytes(), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec iv = new IvParameterSpec(new byte[16]);
                cipher.init(2, secretKeySpec, iv);
                byte[] decryptedBytes = cipher.doFinal(Base64.decode("q7mBQegjhpfIAr0OgfLvH0t/D0Xi0ieG0vd+8ZVW+b4=", 0));
                String decryptedText = new String(decryptedBytes);
                t1.setText(decryptedText);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
```

逻辑很简单，有一个静态方法**get_flag**，比较一个参数a是不是4919，是的话就会解密输出flag，一个AES加密，但是，这里没有任何方法会调用这个静态方法，那么我们就可以利用frida编写脚本调用这个静态方法，并且将参数a的值改为正确的，那么就可以输出flag。使用frida的前期工作和例题一一样，但是因为这是静态方法，如果使用指令**frida -U -f 包名 -l 脚本**会出现hook不上的情况，所以我们可以先运行程序，然后使用指令**frida -U 'Frida 0x2' -l .\Hook.js**，就可以输出flag了。

脚本：

```js
Java.perform(function() {

    // 声明了一个变量a来表示目标Android应用程序中的Java类。
    // Java.use函数指定要使用com.ad2001.frida0x2包中的MainActivity类。
    var a = Java.use("com.ad2001.frida0x2.MainActivity");

    // 调用get_flag方法并传入参数4919
    a.get_flag(4919);

});

```

运行脚本：

![bf377131-0114-495d-9e73-890184a88bf5](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/bf377131-0114-495d-9e73-890184a88bf5.png)

得到flag



**总结**：Frida 调用静态方法的脚本模板：

```js
Java.perform(function (){ 

     var <class_reference> = Java.use(“<package_name>.<class>”); 

     a.function(val); // 需要调用的方法名称 

})
```





------------------------------------------------------------------------------------------------------------------------------------------

##### 五.Frida 用法（3）.js脚本更改变量的值

1.拿到附件apk文件，依旧先安装到雷电模拟器上运行一下看看回显，

![592dae50-4a8b-4703-a6f8-ae27fc3af21f](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/592dae50-4a8b-4703-a6f8-ae27fc3af21f.png)

框框一顿点没什么用，那么就开始用jadx静态分析一波吧，看看函数逻辑，

```java
package com.ad2001.frida0x3;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: classes3.dex */
public class MainActivity extends AppCompatActivity {
    TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button btn = (Button) findViewById(R.id.button);
        this.t1 = (TextView) findViewById(R.id.textView);
        btn.setOnClickListener(new View.OnClickListener() { // from class: com.ad2001.frida0x3.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (Checker.code == 512) {
                    byte[] bArr = new byte[0];
                    Toast.makeText(MainActivity.this.getApplicationContext(), "YOU WON!!!", 1).show();
                    byte[] KeyData = "glass123".getBytes();
                    SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
                    byte[] ecryptedtexttobytes = Base64.getDecoder().decode("MKxsZsY9Usw3ozXKKzTF0ymIaC8rs0AY74GnaKqkUrk=");
                    try {
                        Cipher cipher = Cipher.getInstance("Blowfish");
                        cipher.init(2, KS);
                        byte[] decrypted = cipher.doFinal(ecryptedtexttobytes);
                        String decryptedString = new String(decrypted, Charset.forName("UTF-8"));
                        MainActivity.this.t1.setText(decryptedString);
                        return;
                    } catch (InvalidKeyException e) {
                        throw new RuntimeException(e);
                    } catch (NoSuchAlgorithmException e2) {
                        throw new RuntimeException(e2);
                    } catch (BadPaddingException e3) {
                        throw new RuntimeException(e3);
                    } catch (IllegalBlockSizeException e4) {
                        throw new RuntimeException(e4);
                    } catch (NoSuchPaddingException e5) {
                        throw new RuntimeException(e5);
                    }
                }
                Toast.makeText(MainActivity.this.getApplicationContext(), "TRY AGAIN", 1).show();
            }
        });
    }
}
```

逻辑还是很清晰的，就是**com.ad2001.frida0x3**包的**Checker**类中检查参数code的值是否是512，是的话就会输出flag，再来看看**Checker**类的逻辑，![b84316aa-77aa-4e8b-9af1-a0c7c1c42edf](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/b84316aa-77aa-4e8b-9af1-a0c7c1c42edf.png)

        有个**increase**方法，主函数中有个检测按钮的点击次数，点一次就加2，那么这个题要解出来的话，要么点256次，要么直接解密，但似乎加密的逻辑不是很清晰，再一个方法就是用frida修改code的值，直接改为512，这样一来就可以直接输出flag了。

**脚本**：

```js
/*** 
 * Java.perform 是Frida中的一个函数，用于为脚本创建特殊上下文，
 * 进入此上下文后，可以执行挂钩方法或访问Java类等操作来控制或观察应用程序的行为。
 **/ 

Java.perform(function () {

    // 声明了一个变量a来表示目标Android应用程序中的Java类。
    // Java.use函数指定要使用com.ad2001.frida0x3包中的Checker类。
    var a = Java.use("com.ad2001.frida0x3.Checker");

    // 使用变量a将所选类的code变量值修改为512
    a.code.value = 512; 

});

```

        使用frida还是和前面的步骤一样，然后我们输入指令**frida -U -f com.ad2001.frida0x3 -l hook.js**，然后再使用jadx进行动态调试，为的是控制程序运行，点击两次运行，会出现最开始的页面，最后点击Click me，就会出现flag

![b2eeb84c-a1a9-482b-adc6-f1434a6d376c](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/b2eeb84c-a1a9-482b-adc6-f1434a6d376c.png)

得到flag



**总结**：Frida 更改变量值的脚本模板

```js
Java.perform(function (){ 

     var <class_reference> = Java.use(“<package_name>.<class>”); 

     <class_reference>.<variable>.value = <value>; //需要修改的变量 

})
```







------------------------------------------------------------------------------------------------------------------------------------------

##### 六. Frida 用法（4）.js脚本创建类实例

工具不变，拿到附件apk文件，依旧先安装到雷神模拟器上安装运行一下。没有任何输入框或者按钮，只有一个打招呼的。那么就丢到jadx里分析看看具体函数逻辑，![bc871d60-adf0-4209-8577-98455a572801](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/bc871d60-adf0-4209-8577-98455a572801.png)

这是**MainActivity**类，没啥有用的信息。再看看**Check**类![22979e97-83bc-4149-83e5-29d9e1f54005](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/22979e97-83bc-4149-83e5-29d9e1f54005.png)

判断参数a的值是否是1337，是的话就会把解码的flag输出，但是，这个类以及类中的方法并没有在程序的任何地方被使用，因此我们仅仅打开程序无法获取到flag的值，同时，这里的get_flag方法并不是静态方法。所以我们就可以利用frida创建一个实例，再用这个实例来调用这个方法，进而输出flag。

那么我们就可以开始操作了，前期开始工作是一样的，然后我们直接使用脚本，

```js
Java.perform(function() {

    var check = Java.use("com.ad2001.frida0x4.Check");
    // 声明了一个变量 check 来表示目标 Android 应用程序中的 Java 类。
    // Java.use 函数指定要使用 com.ad2001.frida0x4 包的 Check 类。

    var check_obj = check.$new(); 
    // $new() 是 Frida 中的方法，用于实例化特定类的对象；
    // 使用 $new() 方法创建 Check 类的实例 check_obj。

    var res = check_obj.get_flag(1337); 
    // 使用 check_obj 实例调用 get_flag，并传入参数 1337。
    // 创建一个变量 res 来保存 get_flag 方法的返回值。

    console.log("FLAG：" + res);
    // 将保存的 flag 输出到脚本运行日志中。

});

```

![0feeea01-c0ea-429c-9631-9c1d5e923db3](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/0feeea01-c0ea-429c-9631-9c1d5e923db3.png)

拿到flag



**总结**：Frida 创建类实例的脚本模板

```js
Java.perform(function() {

  var <class_reference> = Java.use("<package_name>.<class>");
  var <class_instance> = <class_reference>.$new(); // 创建类的实例
  <class_instance>.<method>(); // 调用该实例中的方法

})
```







------------------------------------------------------------------------------------------------------------------------------------------

##### 七.Frida 用法（5） .js脚本在现有实例上调用方法

1.拿到附件，还是老样子，先到模拟器运行一下

![335d30a1-e545-422d-9d15-ce5d9c46ba1a](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/335d30a1-e545-422d-9d15-ce5d9c46ba1a.png)

没什么有用的信息，就是一个提示词，没了。开jadx看看逻辑吧，![a2b28eb3-0581-4eee-ac41-5e1b64740e01](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/a2b28eb3-0581-4eee-ac41-5e1b64740e01.png)

可以看到逻辑还是很清晰的，有一个**flag**方法，如果**code**的值是1337，那么就会输出flag，但是该方法没有在程序的任何位置被调用，我们需要借助Frida框架来调用这个方法，以获取flag。跟上一用法相同的是我们需要通过flag方法所在的MainActivity类的实例来调用该方法，但在使用Frida脚本创建MainActivity类的实例会出现错误。

原因：**flag方法是属于MainActivity实例的，而上一题（4）中，check是单独的一个类实例，而MainActivity是Android组件，由于Android的生命周期和线程规则，Android组件需要依赖于应用程序上下文运行，在Frida中，我们缺少必要的上下文。例如：Android UI组件通常需要具有关联Looper的特定线程，如果涉及UI任务，需要在具有活动Looper的主线程上执行。总之，创建MainActivity的实例可能需要应用处于特定状态，并通过Frida管理整个生命周期，并不建议这样做。**

解决方法：**由于创建MainActivity实例是Android应用程序生命周期的一部分，当Android应用程序启动时，系统会创建MainActivity的一个实例（或AndroidManifest.xml文件中指定的启动器活动）。因此，我们可以使用Frida获取MainActivity的实例，然后调用flag方法来获取我们的标志。**

脚本：

```js
/*
Java.performNow是Frida中的一个函数，用于在Java运行时环境中执行代码。
*/

Java.performNow(function() {

  Java.choose('com.ad2001.frida0x5.MainActivity', {
    // Java.choose在运行时枚举作为第一个参数传入的Java类的实例。
    // 第二个参数需要传入包含onMatch和onComplete两个回调函数的选项对象。

      onMatch: function(instance) { 
        // 处理匹配到的类实例的回调函数
        // instance参数表示MainActivity类的每个匹配实例

        console.log("Instance found");
        // 找到实例时打印一条提示信息。
        instance.flag(1337); 
        // 调用flag方法，并传入参数1337。
    },
    onComplete: function() {}
    // 完成操作后的回调函数
  });
});
```

这个题和第二个题一样，需要在app运行起来，然后输入frida -U 'Frida 0x5' -l F:\桌面\5.js，就可以输出flag

![e3f1e801-52ef-4c98-af8d-e41be264623f](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/e3f1e801-52ef-4c98-af8d-e41be264623f.png)





总结：**Frida 在现有实例上调用方法的脚本模板**

```js
  Java.performNow(function() {
  Java.choose('<Package>.<class_Name>', {
    onMatch: function(instance) {
      // 匹配到类实例时进行的操作
    },
    onComplete: function() {}
    // 完成操作后的回调函数
  });
});
```







--------------------------------------------------------------------------------------------------------------------------------------------

##### 八.Frida用法（6） .js脚本 使用对象参数调用的方法

1.拿到apk文件，模拟器运行一下，还是和上一题一样，没有任何可以输入的东西，就一个提示词，没了。

2.看代码逻辑吧，![5de480a5-6ed3-46ec-9813-69be4e34c6c7](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/5de480a5-6ed3-46ec-9813-69be4e34c6c7.png)

代码看下来，就是主要逻辑在**get_flag**方法里，可是这个方法没有被调用，该方法对传入的**Checker**类型参数A进行检查，如果参数A的**num1**变量值等于1234且**num2**变量值等于4321，就会将flag解码并输出。

为了得到方法中的flag，我们需要**获取MainActivity类的实例**来调用这个方法，同时还需要满足方法内部对传入参数A.num1和A.num2变量值的验证。因此，我们还需要**创建**一个**Checker类的实例**，并设置好实例中**num1**和**num2**变量的值，在调用get_flag方法时将这个实例作为参数传递。

那么就可以编写脚本了：

```js
/*
Java.performNow是Frida中的一个函数，用于在Java运行时环境中执行代码。
*/

Java.performNow(function() {

  Java.choose('com.ad2001.frida0x6.MainActivity', {
    // Java.choose在运行时枚举MainActivity类的实例。
    // 第二个参数需要传入包含onMatch和onComplete两个回调函数的选项对象。

    onMatch: function(instance) {
      // 处理匹配到的类实例的回调函数

      console.log("Instance found");
       // 处理匹配到的类实例的回调函数

      var checker = Java.use("com.ad2001.frida0x6.Checker");
       // Java.use函数指定要使用com.ad2001.frida0x6包的Check类。

      var checker_obj  = checker.$new();  
       // 使用$new()方法创建Check类的实例check_obj。
      checker_obj.num1.value = 1234; 
       // 将check_obj实例的num1变量值设置为1234
      checker_obj.num2.value = 4321; 
       // 将check_obj实例的num2变量值设置为4321

      instance.get_flag(checker_obj); 
       // 使用check_obj作为参数；
       // 通过获取到的MainActivity类的实例instance调用get_flag方法

    },
    onComplete: function() {}
  });
});
```

运行脚本，还是一样，先让程序运行起来，然后运行脚本去获取**MainActivity**实例。

![c08a65da-6ad9-4ec7-a418-49658949b813](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/c08a65da-6ad9-4ec7-a418-49658949b813.png)

得到flag





总结：**Frida 使用对象参数调用方法的脚本模板**

```js
Java.performNow(function() {
  Java.choose('<Package>.<class_Name>', {
    onMatch: function(instance) {
      var <class_reference> = Java.use("<package_name>.<class>");
      var <class_instance> = <class_reference>.$new(); // 创建类的实例
      /*
      设置实例参数
      */
      instance.<method>(class_instance); // 使用对象参数调用方法
    },
    onComplete: function() {}
    // 完成操作后的回调函数
  });
});
```







--------------------------------------------------------------------------------------------------------------------------------------------

##### 九.Frida用法（7） .js脚本 Hook构造函数

1.拿到apk安装包，还是先安装到模拟器中运行一下看看先，

![a95132d6-0271-4f2f-a4fa-ec9ea5c416f9](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/a95132d6-0271-4f2f-a4fa-ec9ea5c416f9.png)

还是一样，没有输入框，只有一句提示词，那就用jadx反编译看看吧，

```java
package com.ad2001.frida0x7;

import android.os.Bundle;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: classes3.dex */
public class MainActivity extends AppCompatActivity {
    TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        this.t1 = (TextView) findViewById(R.id.textview);
        Checker ch = new Checker(123, 321);
        try {
            flag(ch);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e2) {
            throw new RuntimeException(e2);
        } catch (BadPaddingException e3) {
            throw new RuntimeException(e3);
        } catch (IllegalBlockSizeException e4) {
            throw new RuntimeException(e4);
        } catch (NoSuchPaddingException e5) {
            throw new RuntimeException(e5);
        }
    }

    public void flag(Checker A) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (A.num1 > 512 && 512 < A.num2) {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec("MySecureKey12345".getBytes(), "AES");
            cipher.init(2, secretKeySpec);
            byte[] decryptedBytes = Base64.getDecoder().decode("cL/bBqDmfO0IXXJCVFwYLeHp1k3mQr+SP6rlQGUPZTY=");
            String decrypted = new String(cipher.doFinal(decryptedBytes));
            this.t1.setText(decrypted);
        }
    }
}
```

分析代码逻辑，并不难，就是有一个**Checker**类的对象，调用flag方法传入该对象，然后对num1和num2的两个值分别进行判断，两个参数必须都大于512，那么就会对flag进行解密输出。

逻辑明白之后，我们就可以编写脚本进行hook，Hook Checker类对象的构造函数Checker(int a, int b)，将参数a，b修改为大于512的值来绕过检验。

脚本：

```js
Java.perform(function (){

  var a = Java.use("com.ad2001.frida0x7.Checker");
    // 声明了一个变量a来表示目标Android应用程序中的Java类。
    // Java.use函数指定要使用com.ad2001.frida0x7包中的Checker类。

  a.$init.implementation = function (a,b){
    // $init关键字Hook Checker类对象创建时执行的构造函数

    console.log("Origin num：",a,b);
    // 打印a,b变量初始化时设置的值

    this.$init(1000,1000);
    // 调用Checker类构造函数将a,b变量值修改为600
  }
})
```

运行脚本，然后利用jadx控制程序运行

![5173e46c-b3cf-419f-8c72-a6696551909f](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/5173e46c-b3cf-419f-8c72-a6696551909f.png)

拿到flag





总结：**Frida Hook构造函数的脚本模板**

```js
Java.perform(function() {
  var <class_reference> = Java.use("<package_name>.<class>");
  <class_reference>.$init.implementation = function(<args>){

    /*
    我们自己的方法实现
    */

  }
});
```







----------------------------------------------------------------------------------------------------------------------------------------------

##### 十.Frida用法（8） .js脚本 Hook native函数

1.拿到附件，安装到模拟器中运行一下，可以看到可以让我们输入字符或者数字，然后点击提交，报错，没了。

2.用jadx静态分析吧，

```java
package com.ad2001.frida0x8;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import com.ad2001.frida0x8.databinding.ActivityMainBinding;

/* loaded from: classes4.dex */
public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;
    Button btn;
    EditText edt;

    public native int cmpstr(String str);

    static {
        System.loadLibrary("frida0x8");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = inflate;
        setContentView(inflate.getRoot());
        this.edt = (EditText) findViewById(R.id.editTextText);
        Button button = (Button) findViewById(R.id.button);
        this.btn = button;
        button.setOnClickListener(new View.OnClickListener() { // from class: com.ad2001.frida0x8.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                String ip = MainActivity.this.edt.getText().toString();
                int res = MainActivity.this.cmpstr(ip);
                if (res == 1) {
                    Toast.makeText(MainActivity.this, "YEY YOU GOT THE FLAG " + ip, 1).show();
                } else {
                    Toast.makeText(MainActivity.this, "TRY AGAIN", 1).show();
                }
            }
        });
    }
}
```

分析代码逻辑，我们可以知道，只有当我们输入的内容是正确的flag时，**cmpstr**方法的返回值是1时，就会输出表示正确的提示词，然后再输出flag。但是我们可以看到该方法是**native**层的，

![7fd743f8-b07c-4e52-b19d-957af40378e5](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/7fd743f8-b07c-4e52-b19d-957af40378e5.png)

那么我们就去**native层**查看该函数的逻辑。我们将附件中的apk文件的后缀，apk改成zip，然后解压缩，然后我们在路径lib->x86_64->libfrida0x8.so，打开libfrida0x8.so文件，用ida64分析，然后找到，![038ef7a8-82f7-45b0-8363-2b9ddcf7e43d](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/038ef7a8-82f7-45b0-8363-2b9ddcf7e43d.png)

就可以看到伪代码，![636e6848-d88a-497a-8b9b-e6886d1836db](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/636e6848-d88a-497a-8b9b-e6886d1836db.png)

可以看到就是**aGsjebObujwfMbo**字符串每一个元素都减一，然后将结果给到Password，最后进行比较，如果与我们输入的字符串进行比较，一样就返回1，否则返回0。由于password 参数只在 native 库中调用的 strcmp 函数中被作为参数传递，那么这里我们就可以通过 Frida 脚本 Hook strcmp 函数来实现。

我们需要编写一个js脚本Hook 应用程序加载的 frida0x8 native 库中 cmpstr 函数使用的 strcmp 函数，并获取函数中使用的参数 password 的值。

以下就是脚本：

第一种：

```js
var strcmp_adr =  Module.findExportByName("libc.so", "strcmp");
// 使用Module.findExportByName()获取libc.so库中strcmp函数的地址。

Interceptor.attach(strcmp_adr, {
  // Hook strcmp_adr地址对应的函数，将onEnter和onLeave回调函数附加到strcmp_adr地址中

  onEnter: function (args) {
    // 在strcmp函数被调用之前执行的回调函数，args是一个指针数组，提供对函数参数的访问。

    console.log("Hooking the strcmp function");
    // 进入strcmp函数时打印提示语"Hooking the strcmp function"

    var flag = Memory.readUtf8String(args[1]); 
    // 使用Memory.readUtf8String()获取password参数；
    // password参数在strcmp函数中的地址为arg[1]。

    console.log("The flag is "+ flag);
    // 打印获取到的password参数值。

  },
  onLeave: function (retval) {
    // 在strcmp函数被调用之后执行的回调函数，它提供对返回值retval的访问。
  }
});
```

但是，这个脚本会把程序中所有的strcmp函数都打印出来，因此，我们可以输入一个特定的字符串（例如：”HELLO”），将其作为 Hook 脚本的过滤器。

```js
var strcmp_adr = Module.findExportByName("libc.so", "strcmp");
// 使用Module.findExportByName()获取libc.so库中strcmp函数的地址。
Z
Interceptor.attach(strcmp_adr, {
  // Hook strcmp_adr地址对应的函数，将onEnter和onLeave回调函数附加到strcmp_adr地址中

    onEnter: function (args) {
      // 在strcmp函数被调用之前执行的回调函数，args是一个指针数组，提供对函数参数的访问。

        var arg0 = Memory.readUtf8String(args[0]);
          // 使用Memory.readUtf8String()读取第一参数inputStr内容。

        var flag = Memory.readUtf8String(args[1]);
          // 使用Memory.readUtf8String()获取第二个参数password内容。

        if (arg0.includes("HELLO")) {
          // 只有当第一个参数值是我们输入的特定字符串"HELLO"时才执行下面的操作。

            console.log("Hooking the strcmp function");
             // 打印提示语"Hooking the strcmp function"

            console.log("Input " + arg0);
             // 打印第一个参数inputStr的值。

            console.log("The flag is "+ flag);
             // 打印第二个参数password的值。

        }
    },
    onLeave: function (retval) {
        // 在strcmp函数被调用之后执行的回调函数，它提供对返回值retval的访问。
    }
});
```

> Memory.readUtf8String()是Frida中用于读取内存中UTF-8编码字符串的函数。它的作用是从指定的内存地址读取UTF-8编码的字符串，并将其转换为JavaScript中的字符串类型。



拿到flag

![c5626169-66af-46d4-85a7-ae73bd1cbca7](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/c5626169-66af-46d4-85a7-ae73bd1cbca7.png)





总结：**Frida Hook native 函数的脚本模板**

```js
Interceptor.attach(targetAddress, {
  // 将回调附加到指定的函数地址，targetAddress为我们想要挂钩的native函数的地址。

  onEnter: function (args) {
    // 在目标函数被调用之前执行的回调函数，提供对函数参数args的访问。

    console.log('Entering ' + functionName);
    // 根据需要修改或记录参数
  },
  onLeave: function (retval) {
    // 在目标函数被调用之后执行的回调函数，它提供对返回值retval的访问。

    console.log('Leaving ' + functionName);
    // 根据需要修改或记录参数
  }
});
```





**补充**：

在前面的学习我们知道，Hook一个函数需要知道调用这个函数的程序包名和类名。而Hook native 函数，我们需要知道这个 native 函数的地址，然后使用 Frida 的 Interceptor API 进行 Hook。

> Interceptor API是Frida中一个功能强大的模块，能够帮助我们 Hook C 函数、Objective-C 方法。
>
> 
>
> Interceptor模块中Interceptor.attach()函数用于拦截函数调用，需要传递两个参数，第一个参数是要拦截的函数地址，第二个参数是包含回调函数的对象，用于定义在目标函数被调用时执行的回调函数，通常包含以下两个回调函数：
>
> * onEnter：在目标函数被调用之前执行的回调函数。在这个回调函数中，可以访问函数的参数，修改参数的值，记录函数调用信息等操作。
>
> * onLeave：在目标函数被调用之后执行的回调函数。在这个回调函数中，可以访问函数的返回值，修改返回值，记录函数执行结果等操作。



**导出函数表**：指的是库文件提供给外部使用的函数或变量。

**导入函数表**：指库文件引用的函数或变量。

在Frida 0x8 的这个例子中，我们的目标函数是 strcmp函数，所以我们可以从 libfrida0x8.so 的导入表或者 libc 的导出表中找到该函数地址。



输出libfrida0x8.so的导出表：Module.enumerateExports("libfrida0x8.so")

找strcmp函数的地址：Module.findExportByName("libc.so", "strcmp")或者                                            Module.enumerateImports("libfrida0x8.so")[4]

----------------------------------------------------------------------------------------------------------------------------------------------

找cmpstr函数的地址：Module.getExportByName("libfrida0x8.so", "Java_com_ad2001_frida0x8_MainActivity_cmpstr")

Module.findExportByName("libfrida0x8.so", "Java_com_ad2001_frida0x8_MainActivity_cmpstr")

Module.findExportByName与 Module.getExportByName 相同。唯一的区别是，如果找不到导出符号，Module.getExportByName 会引发异常，而 Module.findExportByName 会返回 null。



有时，如果上面的 API 获取不到指定函数地址，我们可以使用 Module.getBaseAddress，这个 API 返回给定模块的基地址，我们可以用它来找到 libfrida0x8.so 库的基地址。如果我们想找到一个特定函数的地址，可以在基地址的基础上添加偏移量。cmpstr 函数的偏移量，我们可以在 IDA 中查看

Module.getBaseAddress("libfrida0x8.so").add(0x864)   （0x864是偏移量，可以在ida中看到）![ebecd84b-9b14-4c80-9ee6-8a238b859c11](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/ebecd84b-9b14-4c80-9ee6-8a238b859c11.png)

----------------------------------------------------------------------------------------------------------------------------------------------

**注**：由于 Android 默认启用 ASLR 安全机制，系统启动或程序加载时随机化内存地址空间，如果你重新启动了 APP，前后两次获取到的指定函数地址会有差异。



查看libfrida0x8.so导入符号信息：Module.enumerateImports("libfrida0x8.so")

接着，可以利用下标来访问其中的函数的地址：Module.enumerateImports("libfrida0x8.so")[4]["address"]    [4]就是下标。







------------------------------------------------------------------------------------------------------------------------------------

##### 十一.Frida用法（9）.js脚本 更改native函数的返回值

1.首先还是一样，拿到apk文件，先安装到模拟器上运行一下，结果还是一样，一顿点，然后九只有提示你try angin

![1e770054-8c1c-47c3-aaa7-4d66432e4def](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/1e770054-8c1c-47c3-aaa7-4d66432e4def.png)

2.接着用jadx打开，静态分析一下反编译的Java代码，

```java
package com.ad2001.a0x9;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import com.ad2001.a0x9.databinding.ActivityMainBinding;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: classes3.dex */
public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;
    Button btn;

    public native int check_flag();

    static {
        System.loadLibrary("a0x9");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = inflate;
        setContentView(inflate.getRoot());
        Button button = (Button) findViewById(R.id.button);
        this.btn = button;
        button.setOnClickListener(new View.OnClickListener() { // from class: com.ad2001.a0x9.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (MainActivity.this.check_flag() == 1337) {
                    try {
                        Cipher cipher = Cipher.getInstance("AES");
                        SecretKeySpec secretKeySpec = new SecretKeySpec("3000300030003003".getBytes(), "AES");
                        try {
                            cipher.init(2, secretKeySpec);
                            byte[] decryptedBytes = Base64.getDecoder().decode("hBCKKAqgxVhJMVTQS8JADelBUPUPyDiyO9dLSS3zho0=");
                            try {
                                String decrypted = new String(cipher.doFinal(decryptedBytes));
                                Toast.makeText(MainActivity.this.getApplicationContext(), "You won " + decrypted, 1).show();
                                return;
                            } catch (BadPaddingException e) {
                                throw new RuntimeException(e);
                            } catch (IllegalBlockSizeException e2) {
                                throw new RuntimeException(e2);
                            }
                        } catch (InvalidKeyException e3) {
                            throw new RuntimeException(e3);
                        }
                    } catch (NoSuchAlgorithmException e4) {
                        throw new RuntimeException(e4);
                    } catch (NoSuchPaddingException e5) {
                        throw new RuntimeException(e5);
                    }
                }
                Toast.makeText(MainActivity.this.getApplicationContext(), "Try again", 1).show();
            }
        });
    }
}
```

可以看到在**MainActivity** 类中，有一段native功能声明，使用native关键字定义了一个native函数check_flag，该函数不接受任何参数，同时返回一个参数，然后将 a0x9 库加载到程序中，System.loadLibrary 方法提示我们 a0x9 是 native 库文件，check_flag 函数在 a0x9 库中实现。同时，MainActivity 类中还定义了一个 onClick 方法来监控按钮的点击，当点击应用程序按钮时，onClick 方法会将 check_flag 函数的返回值与1337进行比较，如果它们相等，就会解密 flag 并显示在应用程序界面。否则，打印“Try again”。接下来我们需要使用 IDA 来分析 a0x9 库中的 check_flag 函数。

```java
public native int check_flag();

    static {
        System.loadLibrary("a0x9");
    }
```

```java
public void onClick(View v) {
if (MainActivity.this.check_flag() == 1337) {
    try {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKeySpec = new SecretKeySpec("3000300030003003".getBytes(), "AES");
        try {
            cipher.init(2, secretKeySpec);
            byte[] decryptedBytes = Base64.getDecoder().decode("hBCKKAqgxVhJMVTQS8JADelBUPUPyDiyO9dLSS3zho0=");
            try {
                String decrypted = new String(cipher.doFinal(decryptedBytes));
                Toast.makeText(MainActivity.this.getApplicationContext(), "You won " + decrypted, 1).show();
                return;
            } 
                ...
        }
        Toast.makeText(MainActivity.this.getApplicationContext(), "Try again", 1).show();
    }
```

还是一样，改一下文件后缀名，然后找到liba0x9.so文件，然后用ida64打开，找到对应函数，发现啥逻辑没用，就是一个返回1，![9768b234-8316-4ac0-abf7-27afb009f331](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/9768b234-8316-4ac0-abf7-27afb009f331.png)

那么接下来，我们需要使用 Frida 框架，编写一个 JavaScript 脚本，Hook在应用程序加载的 liba0x9.so native 库中运行的 check_flag 函数，并将它的返回值更改为1337。

通过对 APK 静态分析，我们可以知道 check_flag 函数在 liba0x9.so 库中的名称是Java_com_ad2001_a0x9_MainActivity_check_1flag，同时可以在 liba0x9.so 中的导出表中找到该符号的地址。

以下是脚本：

```js
var check_flag = Module.findExportByName("liba0x9.so", "Java_com_ad2001_a0x9_MainActivity_check_1flag")
// 获取liba0x9.so库中Java_com_ad2001_a0x9_MainActivity_check_1flag函数地址，并将它储存在check_flag中。

Interceptor.attach(check_flag, {
  // Hook check_flag地址对应的函数，将onEnter和onLeave回调函数附加check_flag地址中
  onEnter: function () {
    // 在check_flag函数被调用之前执行的回调函数，根据需要修改或记录参数。

  },
  onLeave: function (retval) {
    // 在check_flag函数被调用之后执行的回调函数，它提供对返回值retval的访问。

    console.log("Original return value :" + retval);
    // 打印函数原本返回值

    retval.replace(1337)  
     // 将check_flag函数返回值修改为1337。
  }
});
```

然后先让程序运行起来，再输入frida -U 'Frida 0x9' -l F:\桌面\9.js

![5125b7ab-1804-4952-a662-7e8f0851a167](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/5125b7ab-1804-4952-a662-7e8f0851a167.png)

FRIDA{NATIVE_LAND_0x2}

就得flag了。







**总结**：Frida 更改native函数返回值的脚本模板

```js
Interceptor.attach(targetAddress, {
  // 将回调附加到指定的函数地址，targetAddress为我们想要挂钩的native函数的地址。

  onEnter: function (args) {
    // 在目标函数被调用之前执行的回调函数，提供对函数参数args的访问。

    console.log('Entering ' + functionName);
    // 根据需要修改或记录参数
  },
  onLeave: function (retval) {
    // 在目标函数被调用之后执行的回调函数，它提供对返回值retval的访问。

    console.log('Leaving ' + functionName);
    // 根据需要修改或记录参数

    retval.replace(value)  
    // 将目标函数返回值修改为value。
  }
});
```







----------------------------------------------------------------------------------------------------------------------

##### 十二.Frida用法（10） .js脚本调用native函数

1.还是一样，拿到apk文件，安装到模拟器上，结果发现在雷电模拟器上安装不了，然后换成夜神模拟器，可以安装但是不可以运行，就很奇怪了。(时隔一年，有了真机，重新来完成这题）。

![86be60ff-22b7-45ff-8bfe-60167c7e3bbe](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/86be60ff-22b7-45ff-8bfe-60167c7e3bbe.png)

2.那就用jadx打开分析一下函数逻辑

```Java
package com.ad2001.frida0xa;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.ad2001.frida0xa.databinding.ActivityMainBinding;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MainActivity.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\u0018\u0000 \u000b2\u00020\u0001:\u0001\u000bB\u0005¢\u0006\u0002\u0010\u0002J\u0012\u0010\u0005\u001a\u00020\u00062\b\u0010\u0007\u001a\u0004\u0018\u00010\bH\u0014J\t\u0010\t\u001a\u00020\nH\u0086 R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000¨\u0006\f"}, d2 = {"Lcom/ad2001/frida0xa/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "binding", "Lcom/ad2001/frida0xa/databinding/ActivityMainBinding;", "onCreate", "", "savedInstanceState", "Landroid/os/Bundle;", "stringFromJNI", "", "Companion", "app_debug"}, k = 1, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes4.dex */
public final class MainActivity extends AppCompatActivity {
    public static final Companion Companion = new Companion(null);
    private ActivityMainBinding binding;

    public final native String stringFromJNI();

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        Intrinsics.checkNotNullExpressionValue(inflate, "inflate(layoutInflater)");
        this.binding = inflate;
        ActivityMainBinding activityMainBinding = null;
        if (inflate == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            inflate = null;
        }
        setContentView(inflate.getRoot());
        ActivityMainBinding activityMainBinding2 = this.binding;
        if (activityMainBinding2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
        } else {
            activityMainBinding = activityMainBinding2;
        }
        activityMainBinding.sampleText.setText(stringFromJNI());
    }

    /* compiled from: MainActivity.kt */
    @Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002¨\u0006\u0003"}, d2 = {"Lcom/ad2001/frida0xa/MainActivity$Companion;", "", "()V", "app_debug"}, k = 1, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes4.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    static {
        System.loadLibrary("frida0xa");
    }
}
```

可以看到应用程序的 MainActivity类中，同样声明了一段native功能：在程序开始时定义了返回值为字符串类型的 native 函数 stringFromJNI，它不接受任何参数；在程序结尾处加载 frida0xa 动态链接库，用于实现 native 函数。MainActivity 类中还定义了onCreate方法，在程序加载时调用 stringFromJNI 函数，将函数返回的 “Hello Hackers”文本设置给 TextView 控件。

![73d70a10-c104-4c25-9830-2c19cf698775](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/73d70a10-c104-4c25-9830-2c19cf698775.png)

3.接下来，我们使用 IDA 对 frida0xa 动态链接库进行分析。

还是一样，先改后缀名，然后找到libfrida0xa.so，用ida64打开，发现函数窗口处一堆函数，并且是用c++写的，直接利用搜索功能找到stringFromJNI函数，可以看到

```c++
__int64 __fastcall Java_com_ad2001_frida0xa_MainActivity_stringFromJNI(_JNIEnv *a1)
{
  const char *v1; // rsi
  __int64 v3; // [rsp+18h] [rbp-48h]
  char v4[24]; // [rsp+40h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  std::string::basic_string<decltype(nullptr)>(v4, "Hello Hackers");
  v1 = (const char *)sub_20690(v4);
  v3 = _JNIEnv::NewStringUTF(a1, v1);
  std::string::~string(v4);
  return v3;
}
```

同时，我们还发现了一个函数，get_flag函数，这个函数我们在Java层并没有看到有引用，![a8f42294-b874-4ff2-b4a3-f6fac741ac4b](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/a8f42294-b874-4ff2-b4a3-f6fac741ac4b.png)

逻辑很简单，可以直接逆，也可以用Frida框架进行调用，然后程序自解密flag并输出

要使用 Frida 脚本调用 native 函数，我们需要创建一个 NativePointer 对象，将要调用的 native 函数地址传递给 NativePointer 构造函数。然后，我们需要创建一个 NativeFunction 对象，来表示我们要调用的实际 native 函数。NativeFunction 对象的第一个参数应是 NativePointer 对象，第二个参数是 native 函数的返回类型，第三个参数是要传递给 native 函数参数的数据类型列表。

> NativePointer：是 Frida 中一个表示 native 内存地址的 JavaScript 对象，它用于在 Frida 脚本中操作和访问 native 内存地址，比如读取或写入内存中的数据，调用内存中的函数等。
>
> 
>
> NativeFunction：是 Frida 中用于在 JavaScript 中调用 native 函数的对象。通过 NativeFunction 对象，可以在 Frida 脚本中调用 native 共享库（如动态链接库）中的函数，实现对 native 函数的调用和控制。

下面就是脚本，具体get_flag函数的地址怎么获取之前有记录

```js
function hook_function() {
  var get_flagAddr = Module.findBaseAddress("libfrida0xa.so").add(0x1dd60);
  var get_flagPtr = new NativePointer(get_flagAddr);
  console.log("find the func");

  var get_flag = new NativeFunction(get_flagPtr, "int", ["int", "int"]);

  var res = get_flag(1, 2);
  console.log(res);
}

setImmediate(function () {
//   Java.perform(function () {
    hook_function();
//   });
}, 1000);
```

运行脚本。
![image-20250725163325106](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250725163325106.png)

可以看到get_flag函数成功被调用并且返回了1，也就是说在日志中成功输出了，打开Android studio看日志，就可以找到flag
![image-20250725163428497](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250725163428497.png)



**总结**：Frida 调用 native 函数脚本模板

```js
var native_adr = new NativePointer(<address_of_the_native_function>);
// 创建一个 NativePointer 对象，用于操作和访问 <address_of_the_native_function>内存地址。

const native_function = new NativeFunction(native_adr, '<return type>', ['argument_data_type']);
// 创建一个 NativeFunction 对象，实现对 native 函数的调用和控制。
// native_adr：使用native_adr NativePointer对象；
// '<return type>'：函数的返回值类型；
// ['argument_data_type']：传递给函数的参数类型列表。

native_function(<arguments>);
// 调用 native_function 函数，如果需要，可以传递<arguments>参数。
```







--------------------------------------------------------------------------------------------------------------------------------------------

##### 十三.Frida用法（11） .js脚本 使用ARM64Writer修改指令

1.这个题和上一个题一样，还是在雷电模拟器上安装不了，然后在夜神模拟器上运行不了，很苦恼，那就只能学思维和操作方法了。(时隔一年，回来继续写，hhhh)

2.用jadx反编译看看函数逻辑

```java
package com.ad2001.frida0xb;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.ad2001.frida0xb.databinding.ActivityMainBinding;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MainActivity.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u0018\u0000 \n2\u00020\u0001:\u0001\nB\u0005¢\u0006\u0002\u0010\u0002J\t\u0010\u0005\u001a\u00020\u0006H\u0086 J\u0012\u0010\u0007\u001a\u00020\u00062\b\u0010\b\u001a\u0004\u0018\u00010\tH\u0014R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000¨\u0006\u000b"}, d2 = {"Lcom/ad2001/frida0xb/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "binding", "Lcom/ad2001/frida0xb/databinding/ActivityMainBinding;", "getFlag", "", "onCreate", "savedInstanceState", "Landroid/os/Bundle;", "Companion", "app_debug"}, k = 1, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes3.dex */
public final class MainActivity extends AppCompatActivity {
    public static final Companion Companion = new Companion(null);
    private ActivityMainBinding binding;

    public final native void getFlag();

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        Intrinsics.checkNotNullExpressionValue(inflate, "inflate(layoutInflater)");
        this.binding = inflate;
        if (inflate == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            inflate = null;
        }
        setContentView(inflate.getRoot());
        View findViewById = findViewById(R.id.button);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.button)");
        Button btn = (Button) findViewById;
        btn.setOnClickListener(new View.OnClickListener() { // from class: com.ad2001.frida0xb.MainActivity$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.onCreate$lambda$0(MainActivity.this, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onCreate$lambda$0(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getFlag();
    }

    /* compiled from: MainActivity.kt */
    @Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002¨\u0006\u0003"}, d2 = {"Lcom/ad2001/frida0xb/MainActivity$Companion;", "", "()V", "app_debug"}, k = 1, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes3.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    static {
        System.loadLibrary("frida0xb");
    }
}
```

可以看到在应用程序的 MainActivity 类中，定义了一个 native 函数 getFlag，该函数不接受任何参数也没有返回值，并在程序结尾处使用 System.loadLibrary 函数加载 frida0xb 动态链接库。MainActivity 类中定义的 onCreate 方法监听按钮的点击，点击按钮时会通过 lambda 表达式调用 onCreate$lambda$0 方法，然后在onCreate$lambda$0 方法中调用 getFlag 函数。接下来，我们使用 IDA 对 frida0xb 动态链接库进行分析，查看 getFlag 函数是如何实现的。

获取.so文件的方法还是一样，改一下后缀名，然后找到对应的.so文件，用ida64打开，找到函数，发现ida反编译出来的伪代码严重不完整

这是反编译的![c1c99ce8-dd3c-45e7-972d-420bc723bb6b](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/c1c99ce8-dd3c-45e7-972d-420bc723bb6b.png)

这是汇编

![b7f9b83b-82c3-4020-8214-7e21221cd822](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/b7f9b83b-82c3-4020-8214-7e21221cd822.png)

我们回到流程控制窗口中查看。可以看到程序中出现永远为假的条件跳转，导致 IDA 识别不到解密 flag 并输出的代码指令![c8c51492-2225-42d3-a08c-fb511b6314c6](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/c8c51492-2225-42d3-a08c-fb511b6314c6.png)

然后一跳转就没了。

分析完代码我们可以发现，程序在点击按钮时调用了 getFlag 函数，该函数在 native 代码实现过程中，有一个永久为假的条件跳转，导致解密 flag 并输出的代码块未被执行。为了获取这个 flag ，我们需要使用 Frida 脚本，修改jnz（跳转到程序结尾）这条指令，让它不执行，以绕过条件跳转来执行解码和输出 flag 的程序。

我们需要使用Frida 框架，编写一个 JavaScript 脚本，将 native 函数 getFlag 中的 B.NE （条件分支跳转指令）修改为 Nop（空操作指令），在Frida中修改汇编指令需要使用ARM64Writer 类。

![fbfa387f-184f-4213-8b0b-f0095d0bf4c3](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/fbfa387f-184f-4213-8b0b-f0095d0bf4c3.png)

首先，我们需要知道 B.NE 指令的地址，该地址同样可以通过Module.getBaseAddress API 得到 frida0xb 库的基地址，再加上 B.NE 指令的偏移量来获取。我们可以在IDA中查看 B.NE 指令地址的偏移量为”0x170CE″。然后创建一个 ARM64Writer 类的实例，将获取到的 B.NE 指令的地址作为传入参数，再调用 ARM64Writer 实例的 putNop 方法在 B.NE 指令的地址上写入一条 Nop 指令，覆盖掉原来的指令。接着调用 ARM64Writer 实例的 flush 方法将修改后的指令写入内存中。![14ee1b95-145b-4648-b0b9-c6ed99e9f2ec](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/14ee1b95-145b-4648-b0b9-c6ed99e9f2ec.png)

为了绕过应用程序中的内存分页保护机制，成功修改并运行 native 代码中的指令，我们还需要使用 Frida 中的 Memory.protect 函数，将指定内存区域的保护属性修改为”rwx”（可读可写可执行）。

> 在Frida中，Memory.protect 函数用于修改内存页的保护属性，以控制对内存的访问权限。这个函数可以用来修改目标进程中的内存页，例如将内存页设置为可读、可写、可执行等。Memory.protect 函数的语法如下：  
>
>    Memory.protect(ptr, size, protection)
>
> * ptr: 表示要修改保护属性的内存地址，通常是一个指向目标内存区域的指针。
>
> * size: 表示要修改保护属性的内存区域的大小，以字节为单位。
>
> * protection: 表示要设置的内存保护属性。

脚本如下

```js
var jnz_adr =  Module.getBaseAddress("libfrida0xb.so").add(0x170CE);
//获取 jnz 指令地址。

Memory.protect(jnz_adr,0x1000,"rwx");
// 将对应内存区域的保护属性修改为可读可写可执行。

var writer = new Arm64Writer(jnz_adr);
// 创建 ARM64Writer 类的实例 writer，将 jnz_adr 作为写入的内存地址。

try{
  writer.putNop();
  // 在原本 jnz 指令的地址上写入一条 Nop 指令，替换原本的 jnz 指令

  writer.flush();
  // 将修改后的指令写入内存中

  console.log("Command modification successful.");
  // 指令修改完成后打印一条提示语。

}finally {
  writer.dispose();
  // 释放与 writer 实例关联的资源。
}
```

脚本还是上面的脚本，运行一下就行了；但是这题应该还可以直接该指令，然后重新打包一下解决的

![image-20250725165131171](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250725165131171.png)

![image-20250725165616883](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250725165616883.png)

完了patch一下，接着用mt管理器重新签名打包一下

然后安装直接运行，就可以在Android studio中找

![image-20250725165813894](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250725165813894.png)



**总结**：Frida使用ARM64Writer修改指令的脚本模板

```js
var writer = new ARM64Writer(<address_of_the_instruction>);
// 创建一个Arm64Writer类实例，用于编写ARM64指令，codeAddress是要写入的内存地址。

try {
  /*
  我们自己的指令实现
  */

  writer.flush();
  // 将修改后的指令写入内存中

} finally {
  writer.dispose();
  // 释放与 ARM64Writer 实例关联的资源。
}
```





##### 十四.Android JAVA层root检测绕过

当看到类似代码检测

```java
    protected void onCreate(Bundle bundle) {
        if (c.a() || c.b() || c.c()) {
            a("Root detected!");
        }
        if (b.a(getApplicationContext())) {
            a("App is debuggable!");
        }
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
    }
```

```java
package sg.vantagepoint.a;

import android.os.Build;
import java.io.File;

/* loaded from: classes.dex */
public class c {
    public static boolean a() {
        for (String str : System.getenv("PATH").split(":")) {
            if (new File(str, "su").exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean b() {
        String str = Build.TAGS;
        return str != null && str.contains("test-keys");
    }

    public static boolean c() {
        for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
            if (new File(str).exists()) {
                return true;
            }
        }
        return false;
    }
}
```

那么我们可以写frida-hook脚本，使得其检测函数返回false，就可以正常在模拟器上运行。

```java
setImmediate(function () {
    console.log("[*] Starting script");

    Java.perform(function () {
        let c = Java.use("sg.vantagepoint.a.c");
        c["a"].implementation = function () {
            return false;
        };

        c["b"].implementation = function () {
            return false;
        };

        c["c"].implementation = function () {

            return false;
        };

    });
})
```

