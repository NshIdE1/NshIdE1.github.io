---
title: HGAME-RE-WEEK1
tags: [CTF, RE, WritesUp, Android]
categories: CTF
---

# HGAME-RE-WEEK1

## week1

### compress_dot_new

附件中给了一个脚本，丢给ai分析，可知这是一个哈夫曼树的创建，在enc.txt中，给了创建的哈夫曼树，同时给了哈夫曼编码，写个脚本进行解压缩

```python
import json


class HuffmanNode:
    def __init__(self, left=None, right=None, value=None):
        self.left = left  # 左子树 (路径0)
        self.right = right  # 右子树 (路径1)
        self.value = value  # ASCII码值


def build_huffman_tree(json_data):
    """递归构建霍夫曼树"""
    if 's' in json_data:
        return HuffmanNode(value=json_data['s'])
    return HuffmanNode(
        left=build_huffman_tree(json_data['a']),
        right=build_huffman_tree(json_data['b'])
    )


def generate_codes(node, prefix="", code_map=None):
    """生成霍夫曼编码表"""
    if code_map is None:
        code_map = {}

    if node.value is not None:
        code_map[node.value] = prefix
    else:
        generate_codes(node.left, prefix + "0", code_map)
        generate_codes(node.right, prefix + "1", code_map)
    return code_map


def decode_huffman(bit_str, root):
    """使用霍夫曼树解码二进制字符串"""
    result = []
    current_node = root

    for bit in bit_str:
        if bit == '0':
            current_node = current_node.left
        else:
            current_node = current_node.right

        if current_node.value is not None:
            result.append(current_node.value)
            current_node = root  # 重置到根节点

    return bytes(result).decode('latin-1')


# 输入数据
json_str = '''
{"a":{"a":{"a":{"a":{"a":{"s":125},"b":{"a":{"s":119},"b":{"s":123}}},"b":{"a":{"s":104},"b":{"s":105}}},"b":{"a":{"s":101},"b":{"s":103}}},"b":{"a":{"a":{"a":{"s":10},"b":{"s":13}},"b":{"s":32}},"b":{"a":{"s":115},"b":{"s":116}}}},"b":{"a":{"a":{"a":{"a":{"a":{"s":46},"b":{"s":48}},"b":{"a":{"a":{"s":76},"b":{"s":78}},"b":{"a":{"s":83},"b":{"a":{"s":68},"b":{"s":69}}}}},"b":{"a":{"a":{"s":44},"b":{"a":{"s":33},"b":{"s":38}}},"b":{"s":45}}},"b":{"a":{"a":{"s":100},"b":{"a":{"s":98},"b":{"s":99}}},"b":{"a":{"a":{"s":49},"b":{"s":51}},"b":{"s":97}}}},"b":{"a":{"a":{"a":{"s":117},"b":{"s":118}},"b":{"a":{"a":{"s":112},"b":{"s":113}},"b":{"s":114}}},"b":{"a":{"a":{"s":108},"b":{"s":109}},"b":{"a":{"s":110},"b":{"s":111}}}}}}
'''

# 构建霍夫曼树
data = json.loads(json_str)
root = build_huffman_tree(data)

# 生成编码表
code_table = generate_codes(root)

# 查看部分编码示例（ASCII到二进制）
print("霍夫曼编码表示例：")
for char in [125, 119, 123, 104, 105, 101, 103, 10]:
    print(f"ASCII {char} ({chr(char) if char > 31 else '控制符'}) -> {code_table[char]}")

# 示例二进制字符串（从 enc.txt 中提取）
compressed_bits = "00010001110111111010010000011100010111000100111000110000100010111001110010011011010101111011101100110100011101101001110111110111011011001110110011110011110110111011101101011001111011001111000111001101111000011001100001011011101100011100101001110010111001111000011000101001010000000100101000100010011111110110010111010101000111101000110110001110101011010011111111001111111011010101100001101110101101111110100100111100100010110101111111111100110001010101101110010011111000110110101101111010000011110100000110110101011000111111000110101001011100000110111100000010010100010001011100011100111001011101011111000101010110101111000001100111100011100101110101111100010110101110000010100000010110001111011100011101111110101010010011101011100100011110010010110111101110111010111110110001111010101110010001011100100101110001011010100001110101000101111010100110001110101011101100011011011000011010000001011000111011111111100010101011100000"

# 解码二进制字符串
decoded_text = decode_huffman(compressed_bits, root)
print("\n解码结果:", decoded_text)
```

hgame{Nu-Shell-scr1pts-ar3-1nt3r3st1ng-t0-wr1te-&-use!}



### Turtle

查下来有壳，upx壳，并且改了特征值，010修改之后，还是脱不了，我在修改特征值的时候就发现少了UPX!，果然修改好之后工具还是一把梭不了，那就只能手脱，x64dbg直接手脱

拿到未修复的脱壳exe，大体逻辑就是先输入一个七位的key，然后进行标准的RC4加密，但是密文的加密并没有用加密后的key来加密，还是使用输入时的key，密文的RC4进行了魔改，不是异或，是相减

```c
__int64 sub_401876()
{
  char sbox1[256]; // [rsp+20h] [rbp-60h] BYREF
  char v2[48]; // [rsp+120h] [rbp+A0h] BYREF
  char flag[46]; // [rsp+150h] [rbp+D0h] BYREF
  char Buf2[5]; // [rsp+17Eh] [rbp+FEh] BYREF
  char v5[2]; // [rsp+183h] [rbp+103h] BYREF
  char input_key[8]; // [rsp+185h] [rbp+105h] BYREF
  char Dest[8]; // [rsp+18Dh] [rbp+10Dh] BYREF
  char key1[11]; // [rsp+195h] [rbp+115h] BYREF
  int v9; // [rsp+1A0h] [rbp+120h]
  int v10; // [rsp+1A4h] [rbp+124h]
  int v11; // [rsp+1A8h] [rbp+128h]
  int v12; // [rsp+1ACh] [rbp+12Ch]

  sub_401C20();
  strcpy(key1, "yekyek");
  Buf2[0] = 0xCD;
  Buf2[1] = 0x8F;
  Buf2[2] = 0x25;
  Buf2[3] = 0x3D;
  Buf2[4] = 0xE1;
  qmemcpy(v5, "QJ", sizeof(v5));
  v2[0] = 0xF8;
  v2[1] = 0xD5;
  v2[2] = 0x62;
  v2[3] = 0xCF;
  v2[4] = 0x43;
  v2[5] = 0xBA;
  v2[6] = 0xC2;
  v2[7] = 0x23;
  v2[8] = 0x15;
  v2[9] = 0x4A;
  v2[10] = 0x51;
  v2[11] = 0x10;
  v2[12] = 0x27;
  v2[13] = 0x10;
  v2[14] = 0xB1;
  v2[15] = 0xCF;
  v2[16] = 0xC4;
  v2[17] = 9;
  v2[18] = 0xFE;
  v2[19] = 0xE3;
  v2[20] = 0x9F;
  v2[21] = 0x49;
  v2[22] = 0x87;
  v2[23] = 0xEA;
  v2[24] = 0x59;
  v2[25] = 0xC2;
  v2[26] = 7;
  v2[27] = 0x3B;
  v2[28] = 0xA9;
  v2[29] = 0x11;
  v2[30] = 0xC1;
  v2[31] = 0xBC;
  v2[32] = 0xFD;
  v2[33] = 0x4B;
  v2[34] = 0x57;
  v2[35] = 0xC4;
  v2[36] = 0x7E;
  v2[37] = 0xD0;
  v2[38] = 0xAA;
  v2[39] = 0xA;
  v12 = 6;
  v11 = 7;
  v10 = 40;
  j_printf("plz input the key: ");
  j_scanf("%s", input_key);
  j__mbscpy(Dest, input_key);
  v9 = 7;
  init(key1, v12, sbox1);
  RC4(input_key, v9, sbox1);
  if ( !j_memcmp(input_key, Buf2, v11) )
  {
    j_printf("plz input the flag: ");
    j_scanf("%s", flag);
    *&key1[7] = 40;
    init(Dest, v9, sbox1);
    sub_40175A(flag, *&key1[7], sbox1);
    if ( !j_memcmp(flag, v2, v10) )
      j_puts(Buffer);
    else
      j_puts(aWrongPlzTryAga);
  }
  else
  {
    j_puts(aKeyIsWrong);
  }
  return 0i64;
}
```

![image-20250203212214952](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250203212214952.png)

直接脚本解密

```c
#include<stdio.h> 
#include<stdlib.h>
#include<string.h> 
int init(unsigned char* s, unsigned char* key, unsigned long Len_k)
{
    
	int i = 0, j = 0;
	char k[256] = { 0 };
	unsigned char tmp = 0;
	for (i = 0; i < 256; i++) {
		s[i] = i;
		k[i] = key[i % Len_k];
	}
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
	return 0; 
}


int rc4(unsigned char* Data, unsigned long Len_D, unsigned char* key, unsigned long Len_k) 
{
	
	unsigned char s[256];
	init(s, key, Len_k);
	int i = 0, j = 0, t = 0;
	unsigned long k = 0;
	unsigned char tmp;
	
	for (k = 0; k < Len_D; k++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		t = (s[i] + s[j]) % 256;
		Data[k] = Data[k] ^ s[t];
	}
	return 0; 
}
int main()
{
	
	unsigned char key[] = "yekyek";                                 //密钥生成的过程
	

	printf("%s\n",key);
	unsigned long key_len = sizeof(key) - 1;
	unsigned char qw[] = {0xcd, 0x8f, 0x25, 0x3d, 0xe1, 0x51, 0x4a};//密文
	rc4(qw, sizeof(qw), key, key_len);
	for (int i = 0; i < sizeof(qw); i++)
	{ 
		printf("%c",qw[i]);  
	}
	return 0;
}
```

拿到key

**ecg4ab6**

```c
#include<stdio.h> 
#include<stdlib.h>
#include<string.h> 
int init(unsigned char* s, unsigned char* key, unsigned long Len_k)
{
    
	int i = 0, j = 0;
	char k[256] = { 0 };
	unsigned char tmp = 0;
	for (i = 0; i < 256; i++) {
		s[i] = i;
		k[i] = key[i % Len_k];
	}
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
	return 0; 
}


int rc4(unsigned char* Data, unsigned long Len_D, unsigned char* key, unsigned long Len_k) 
{
	
	unsigned char s[256];
	init(s, key, Len_k);
	int i = 0, j = 0, t = 0;
	unsigned long k = 0;
	unsigned char tmp;
	
	for (k = 0; k < Len_D; k++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		t = (s[i] + s[j]) % 256;
		Data[k] = Data[k] + s[t];
	}
	return 0; 
}
int main()
{
	
	unsigned char key[] = "ecg4ab6";                                 //密钥生成的过程
	

	printf("%s\n",key);
	unsigned long key_len = sizeof(key) - 1;
	unsigned char qw[40];
    qw[0] = 0xF8;
  qw[1] = 0xD5;
  qw[2] = 0x62;
  qw[3] = 0xCF;
  qw[4] = 0x43;
  qw[5] = 0xBA;
  qw[6] = 0xC2;
  qw[7] = 0x23;
  qw[8] = 0x15;
  qw[9] = 0x4A;
  qw[10] = 0x51;
  qw[11] = 0x10;
  qw[12] = 0x27;
  qw[13] = 0x10;
  qw[14] = 0xB1;
  qw[15] = 0xCF;
  qw[16] = 0xC4;
  qw[17] = 9;
  qw[18] = 0xFE;
  qw[19] = 0xE3;
  qw[20] = 0x9F;
  qw[21] = 0x49;
  qw[22] = 0x87;
  qw[23] = 0xEA;
  qw[24] = 0x59;
  qw[25] = 0xC2;
  qw[26] = 7;
  qw[27] = 0x3B;
  qw[28] = 0xA9;
  qw[29] = 0x11;
  qw[30] = 0xC1;
  qw[31] = 0xBC;
  qw[32] = 0xFD;
  qw[33] = 0x4B;
  qw[34] = 0x57;
  qw[35] = 0xC4;
  qw[36] = 0x7E;
  qw[37] = 0xD0;
  qw[38] = 0xAA;
  qw[39] = 0xA;//密文
	rc4(qw, sizeof(qw), key, key_len);
	for (int i = 0; i < sizeof(qw); i++)
	{ 
		printf("%c",qw[i]);  
	}
	return 0;
}
```

拿到flag

hgame{Y0u'r3_re4l1y_g3t_0Ut_of_th3_upX!}





### Delta_erro0000ors

这题的考点是异常检测，ida一分析，看到汇编就不难发现

![image-20250205152314798](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205152314798.png)

那么我们可以找到异常跳转的地方，下好断点，避免待会下断点调试时程序跑飞

![image-20250205152454960](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205152454960.png)

然后构造假flag进行输入动调

输入flag后，F9运行，会弹出

![image-20250205152552734](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205152552734.png)

点击ok

再继续F9运行，其实F8步过也可以，会弹出

![image-20250205152721361](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205152721361.png)

第一次捕获异常，点No，然后后面点Yes，就可以成功跳转到except

此时程序要求我们输入一个32位的md5，一样，随意输入32位的字符串

但在这里，我们分析汇编可知，输入的字符串，经过处理之后会存储到**rdi**里，我们双击**rdi**，然后F2下硬件断点，因为经过尝试，发现不下硬件断点好像断不下来，在下一次异常跳转的时候，程序会直接跑飞

![image-20250205153018534](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205153018534.png)

![image-20250205153107399](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205153107399.png)

![image-20250205153041819](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205153041819.png)

然后多次F9运行

发现这里有一个比较

![image-20250205153203042](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205153203042.png)

寄存器**rcx**的值就是与我们输入的md5的值进行比较的硬编码，提取出来，重新动调并输入

![image-20250205153309857](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205153309857.png)

然后重复上面的操作，F9运行，最终断下来

![image-20250205154608285](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205154608285.png)

然后可以提取到异或的key值

![image-20250205154706200](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205154706200.png)

![image-20250205154726756](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205154726756.png)

就可以写脚本解密了

本题的整体逻辑就是，先输入flag并且检查格式，然后再要求输入一个md5值与程序内设定的一个值进行比较，如果正确才会对flag进行异或加密

```python
enc = [0x3B, 0x02, 0x17, 0x08, 0x0B, 0x5B, 0x4A, 0x52, 0x4D, 0x11,
       0x11, 0x4B, 0x5C, 0x43, 0x0A, 0x13, 0x54, 0x12, 0x46, 0x44,
       0x53, 0x59, 0x41, 0x11, 0x0C, 0x18, 0x17, 0x37, 0x30, 0x48,
       0x15, 0x07, 0x5A, 0x46, 0x15, 0x54, 0x1B, 0x10, 0x43, 0x40,
       0x5F, 0x45, 0x5A]
key = [0x53, 0x65, 0x76, 0x65, 0x6E, 0x20, 0x73, 0x61, 0x79,
       0x73, 0x20, 0x79, 0x6F, 0x75, 0x27, 0x72, 0x65, 0x20, 0x72,
       0x69, 0x67, 0x68, 0x74, 0x21, 0x21, 0x21, 0x21, 0]
for i in range(len(enc)):
    print(chr(enc[i] ^ key[i % len(key)]), end="")
```

hgame{934b1236-a124-4150-967c-cb4ff5bcc900}





### zundujiadu

安卓题，分析Java层

MainActivity

```java
package com.nobody.zunjia;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.navigation.NavController;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;
import com.nobody.zunjia.databinding.ActivityMainBinding;

/* loaded from: classes3.dex */
public class MainActivity extends AppCompatActivity {
    private AppBarConfiguration appBarConfiguration;
    private ActivityMainBinding binding;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(this.binding.getRoot());
        setSupportActionBar(this.binding.toolbar);
        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment_content_main);
        this.appBarConfiguration = new AppBarConfiguration.Builder(navController.getGraph()).build();
        NavigationUI.setupActionBarWithNavController(this, navController, this.appBarConfiguration);
    }

    @Override // androidx.appcompat.app.AppCompatActivity
    public boolean onSupportNavigateUp() {
        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment_content_main);
        return NavigationUI.navigateUp(navController, this.appBarConfiguration) || super.onSupportNavigateUp();
    }
}
```

jiadu

```java
package com.nobody.zunjia;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.fragment.app.Fragment;
import androidx.navigation.fragment.NavHostFragment;
import com.nobody.zunjia.databinding.FragmentSecondBinding;

/* loaded from: classes3.dex */
public class jiadu extends Fragment {
    private FragmentSecondBinding binding;

    @Override // androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        this.binding = FragmentSecondBinding.inflate(inflater, container, false);
        return this.binding.getRoot();
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        ImageView JiaDu = this.binding.jiaduimage;
        final Bundle bundle = getArguments();
        JiaDu.setOnClickListener(new View.OnClickListener() { // from class: com.nobody.zunjia.jiadu.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                String ZunduJiadu;
                String ZunduJiadu2 = bundle.getString("zunjia");
                if (ZunduJiadu2 == null) {
                    ZunduJiadu = "o.0";
                } else if (ZunduJiadu2.length() < 36) {
                    ZunduJiadu = ZunduJiadu2 + "o.0";
                } else {
                    ZunduJiadu = "The length is too large";
                }
                bundle.putString("zunjia", ZunduJiadu);
                toast to = new toast(jiadu.this.getContext());
                to.setText(ZunduJiadu);
                to.setDuration(0);
                to.show();
            }
        });
        this.binding.buttonSecond.setOnClickListener(new View.OnClickListener() { // from class: com.nobody.zunjia.jiadu$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                jiadu.this.m214lambda$onViewCreated$0$comnobodyzunjiajiadu(bundle, view2);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$onViewCreated$0$com-nobody-zunjia-jiadu, reason: not valid java name */
    public /* synthetic */ void m214lambda$onViewCreated$0$comnobodyzunjiajiadu(Bundle bundle, View v) {
        NavHostFragment.findNavController(this).navigate(R.id.action_SecondFragment_to_FirstFragment, bundle);
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        this.binding = null;
    }
}
```

toast

```Java
package com.nobody.zunjia;

import android.content.Context;
import android.widget.Toast;

/* loaded from: classes3.dex */
public class toast extends Toast {
    private Context mycontext;

    static native void check(Context context, String str);

    public toast(Context context) {
        super(context);
        this.mycontext = context;
    }

    @Override // android.widget.Toast
    public void setText(CharSequence s) {
        super.setText(s);
        check(this.mycontext, (String) DexCall.callDexMethod(this.mycontext, this.mycontext.getString(R.string.dex), this.mycontext.getString(R.string.classname), this.mycontext.getString(R.string.func1), s));
    }
}
```

其他的就不贴出来了

整体逻辑就是运行app，然后通过0.o和o.0的不同组合，总长度为36，然后动态调用一个dex，对该字符串进行处理，接着将加密结果作为key传到so层进行标准的RC4加密

接下来就是dump下运行时的dex，因为动态调用这个dex时，是通过so层的逻辑来进行解密assets文件夹里的dex文件，是个对称加密，在使用完该dex文件后，就会在内存中将其删除。于是乎暴力点，写个Frida hook脚本，将运行时所调用的dex文件全部dump下来，下面是脚本

```js
function get_self_process_name() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

    var readPtr = Module.getExportByName("libc.so", "read");
    var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);

    var path = Memory.allocUtf8String("/proc/self/cmdline");
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);

        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }

    return "-1";
}


function mkdir(path) {
    var mkdirPtr = Module.getExportByName('libc.so', 'mkdir');
    var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);



    var opendirPtr = Module.getExportByName('libc.so', 'opendir');
    var opendir = new NativeFunction(opendirPtr, 'pointer', ['pointer']);

    var closedirPtr = Module.getExportByName('libc.so', 'closedir');
    var closedir = new NativeFunction(closedirPtr, 'int', ['pointer']);

    var cPath = Memory.allocUtf8String(path);
    var dir = opendir(cPath);
    if (dir != 0) {
        closedir(dir);
        return 0;
    }
    mkdir(cPath, 755);
    chmod(path);
}

function chmod(path) {
    var chmodPtr = Module.getExportByName('libc.so', 'chmod');
    var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
    var cPath = Memory.allocUtf8String(path);
    chmod(cPath, 755);
}

function dump_dex() {
    var libart = Process.findModuleByName("libart.so");
    var addr_DefineClass = null;
    var symbols = libart.enumerateSymbols();
    for (var index = 0; index < symbols.length; index++) {
        var symbol = symbols[index];
        var symbol_name = symbol.name;
        //这个DefineClass的函数签名是Android9的
        //_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
        if (symbol_name.indexOf("ClassLinker") >= 0 &&
            symbol_name.indexOf("DefineClass") >= 0 &&
            symbol_name.indexOf("Thread") >= 0 &&
            symbol_name.indexOf("DexFile") >= 0) {
            console.log(symbol_name, symbol.address);
            addr_DefineClass = symbol.address;
        }
    }
    var dex_maps = {};
    var dex_count = 1;

    console.log("[DefineClass:]", addr_DefineClass);
    if (addr_DefineClass) {
        Interceptor.attach(addr_DefineClass, {
            onEnter: function(args) {
                var dex_file = args[5];
                //ptr(dex_file).add(Process.pointerSize) is "const uint8_t* const begin_;"
                //ptr(dex_file).add(Process.pointerSize + Process.pointerSize) is "const size_t size_;"
                var base = ptr(dex_file).add(Process.pointerSize).readPointer();
                var size = ptr(dex_file).add(Process.pointerSize + Process.pointerSize).readUInt();

                if (dex_maps[base] == undefined) {
                    dex_maps[base] = size;
                    var magic = ptr(base).readCString();
                    if (magic.indexOf("dex") == 0) {

                        var process_name = get_self_process_name();
                        if (process_name != "-1") {
                            var dex_dir_path = "/data/data/" + process_name + "/files/dump_dex_" + process_name;
                            mkdir(dex_dir_path);
                            var dex_path = dex_dir_path + "/class" + (dex_count == 1 ? "" : dex_count) + ".dex";
                            console.log("[find dex]:", dex_path);
                            var fd = new File(dex_path, "wb");
                            if (fd && fd != null) {
                                dex_count++;
                                var dex_buffer = ptr(base).readByteArray(size);
                                fd.write(dex_buffer);
                                fd.flush();
                                fd.close();
                                console.log("[dump dex]:", dex_path);

                            }
                        }
                    }
                }
            },
            onLeave: function(retval) {}
        });
    }
}

var is_hook_libart = false;

function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                //console.log("dlopen:", path);
                if (path.indexOf("libart.so") >= 0) {
                    this.can_hook_libart = true;
                    console.log("[dlopen:]", path);
                }
            }
        },
        onLeave: function(retval) {
            if (this.can_hook_libart && !is_hook_libart) {
                dump_dex();
                is_hook_libart = true;
            }
        }
    })

    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function(args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                //console.log("android_dlopen_ext:", path);
                if (path.indexOf("libart.so") >= 0) {
                    this.can_hook_libart = true;
                    console.log("[android_dlopen_ext:]", path);
                }
            }
        },
        onLeave: function(retval) {
            if (this.can_hook_libart && !is_hook_libart) {
                dump_dex();
                is_hook_libart = true;
            }
        }
    });
}


setImmediate(dump_dex);
```

运行脚本之后，多点几次图片运行app，dump下来了很多dex，但是可以发现，前几个就是app中的那几个dex，后面的就应该都是一样的了，也就是对key进行加密的逻辑，先进行异或，然后进行换表的base64编码‘

```java
package com.nobody;

/* loaded from: C:\Users\16219\Desktop\dump_dex_com.nobody.zunjia\class85.dex */
public class zundujiadu {
    private static final String CUSTOM_ALPHABET = "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5";
    private static final int[] DECODE_TABLE = new int[128];

    public zundujiadu() {
        for (int i = 0; i < DECODE_TABLE.length; i++) {
            DECODE_TABLE[i] = -1;
        }
        for (int i2 = 0; i2 < CUSTOM_ALPHABET.length(); i2++) {
            DECODE_TABLE[CUSTOM_ALPHABET.charAt(i2)] = i2;
        }
    }

    public String encode(String str) {
        int i;
        byte b;
        byte b2;
        if (str == null) {
            return null;
        }
        byte[] bytes = str.getBytes();
        int length = bytes.length;
        for (int i2 = 0; i2 < length; i2++) {
            bytes[i2] = (byte) (bytes[i2] ^ i2);
        }
        byte[] bArr = new byte[((length + 2) / 3) * 4];
        int i3 = 0;
        int i4 = 0;
        while (i3 < length) {
            int i5 = i3 + 1;
            byte b3 = bytes[i3];
            if (i5 < length) {
                i = i5 + 1;
                b = bytes[i5];
            } else {
                i = i5;
                b = 0;
            }
            if (i < length) {
                b2 = bytes[i];
                i++;
            } else {
                b2 = 0;
            }
            int i6 = ((b3 & 255) << 16) | ((b & 255) << 8) | (b2 & 255);
            int i7 = i4 + 1;
            bArr[i4] = (byte) CUSTOM_ALPHABET.charAt((i6 >> 18) & 63);
            int i8 = i7 + 1;
            bArr[i7] = (byte) CUSTOM_ALPHABET.charAt((i6 >> 12) & 63);
            int i9 = i8 + 1;
            bArr[i8] = (byte) CUSTOM_ALPHABET.charAt((i6 >> 6) & 63);
            i4 = i9 + 1;
            bArr[i9] = (byte) CUSTOM_ALPHABET.charAt(i6 & 63);
            i3 = i;
        }
        return new String(bArr);
    }

    public String encode(byte[] bArr) {
        int i;
        byte b;
        byte b2;
        if (bArr == null) {
            return null;
        }
        int length = bArr.length;
        for (int i2 = 0; i2 < length; i2++) {
            bArr[i2] = (byte) (bArr[i2] ^ i2);
        }
        byte[] bArr2 = new byte[((length + 2) / 3) * 4];
        int i3 = 0;
        int i4 = 0;
        while (i3 < length) {
            int i5 = i3 + 1;
            byte b3 = bArr[i3];
            if (i5 < length) {
                i = i5 + 1;
                b = bArr[i5];
            } else {
                i = i5;
                b = 0;
            }
            if (i < length) {
                b2 = bArr[i];
                i++;
            } else {
                b2 = 0;
            }
            int i6 = ((b3 & 255) << 16) | ((b & 255) << 8) | (b2 & 255);
            int i7 = i4 + 1;
            bArr2[i4] = (byte) CUSTOM_ALPHABET.charAt((i6 >> 18) & 63);
            int i8 = i7 + 1;
            bArr2[i7] = (byte) CUSTOM_ALPHABET.charAt((i6 >> 12) & 63);
            int i9 = i8 + 1;
            bArr2[i8] = (byte) CUSTOM_ALPHABET.charAt((i6 >> 6) & 63);
            i4 = i9 + 1;
            bArr2[i9] = (byte) CUSTOM_ALPHABET.charAt(i6 & 63);
            i3 = i;
        }
        return new String(bArr2);
    }

    public String decode(String str) {
        if (str == null) {
            return null;
        }
        String replace = str.replace("=", "");
        int length = replace.length();
        if (length % 4 != 0) {
            throw new IllegalArgumentException("输入的 Base64 字符串长度不是 4 的倍数");
        }
        int i = (length * 3) / 4;
        byte[] bArr = new byte[i];
        int i2 = 0;
        int i3 = 0;
        while (i2 < length) {
            int i4 = 0;
            int i5 = 0;
            while (i4 < 4) {
                int i6 = i2 + 1;
                char charAt = replace.charAt(i2);
                if (charAt < 0 || charAt >= DECODE_TABLE.length || DECODE_TABLE[charAt] == -1) {
                    throw new IllegalArgumentException("输入的 Base64 字符串包含非法字符: " + charAt);
                }
                i5 |= DECODE_TABLE[charAt] << ((3 - i4) * 6);
                i4++;
                i2 = i6;
            }
            int i7 = i3 + 1;
            bArr[i3] = (byte) ((i5 >> 16) & 255);
            if (i7 < i) {
                bArr[i7] = (byte) ((i5 >> 8) & 255);
                i7++;
            }
            if (i7 >= i) {
                i3 = i7;
            } else {
                i3 = i7 + 1;
                bArr[i7] = (byte) (i5 & 255);
            }
        }
        for (int i8 = 0; i8 < i3; i8++) {
            bArr[i8] = (byte) (bArr[i8] ^ i8);
        }
        return new String(bArr, 0, i3);
    }
}
```

然后就是so层的rc4

![image-20250205190817166](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20250205190817166.png)

那么接下来就是爆破，0.o和o.0的组合，利用递归调用来爆破

```python
from Crypto.Cipher import ARC4
import base64
import threading

# 待解密的数据
data = [0x7A, 0xC7, 0xC7, 0x94, 0x51, 0x82, 0xF5, 0x99, 0x0C, 0x30,
        0xC8, 0xCD, 0x97, 0xFE, 0x3D, 0xD2, 0xAE, 0x0E, 0xBA, 0x83,
        0x59, 0x87, 0xBB, 0xC6, 0x35, 0xE1, 0x8C, 0x59, 0xEF, 0xAD,
        0xFA, 0x94, 0x74, 0xD3, 0x42, 0x27, 0x98, 0x77, 0x54, 0x3B,
        0x46, 0x5E, 0x95]


# 自定义字符集映射
def get_key(key):
    string1 = "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5"
    string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    old_key = [ord(i) for i in key]
    for i in range(len(key)):
        old_key[i] ^= i
    res = bytes(old_key)
    return base64.b64encode(res).decode().translate(str.maketrans(string2, string1))


# RC4解密
def rc4(key):
    cipher = ARC4.new(key.encode())
    return cipher.decrypt(bytes(data))


# 优化的递归方法，使用缓存避免重复计算
def boom(str, cache):
    if len(str) == 36:
        return

    # 查找缓存
    if str in cache:
        return

    cache.add(str)  # 将当前字符串加入缓存

    res_o0 = get_key(str + "o.0")
    flag_o0 = rc4(res_o0)
    if b"hgame{" in flag_o0 and b"}" in flag_o0:
        print(flag_o0.decode())
        print(str + "o.0")

    res_0o = get_key(str + "0.o")
    flag_0o = rc4(res_0o)
    if b"hgame{" in flag_0o and b"}" in flag_0o:
        print(flag_0o.decode())
        print(str + "0.o")

    # 递归调用
    boom(str + "o.0", cache)
    boom(str + "0.o", cache)


# 使用线程池加速处理
def start_multithreaded_search():
    cache = set()  # 用集合做缓存，避免重复处理相同的字符串
    threads = []

    # 通过多线程加速递归过程
    for i in range(5):  # 创建多个线程进行并行处理
        t = threading.Thread(target=boom, args=("", cache))
        threads.append(t)
        t.start()

    # 等待所有线程执行完毕
    for t in threads:
        t.join()


# 主函数
if __name__ == "__main__":
    start_multithreaded_search()
```

hgame{4af153b9-ed3e-420b-978c-eeff72318b49}
o.00.oo.00.oo.0o.00.o0.o0.o0.o0.o