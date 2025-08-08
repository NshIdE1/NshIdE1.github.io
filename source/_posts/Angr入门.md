---
title: Angr入门
tags: [符号执行]
categories: Angr入门
---

# Angr入门

### 一.前言

**angr_ctf项目**：[GitHub - jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)

​     angr是一个支持多处理架构的用于二进制文件分析的工具包，它提供了动态符号执行的能力以及多种静态分析的能力。项目创建的初衷，是为了整合此前多种二进制分析方式的优点，并开发一个平台，以供二进制分析人员比较不同二进制分析方式的优劣，并根据自身需要开发新的二进制分析系统和方式。

​     angr_ctf则是一个专门针对angr的项目，里面有17个angr相关的题目。这些题目只有一个唯一的要求：你需要找出能够使程序输出“Good Job”的输入，这也是符号执行常见的应用场景。

![image-20241005174038492](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20241005174038492.png)

前面的18个文件夹分别对应每个题目附件的源码，然后dist文件夹里是编译好的题目附件，均是32bit的.ELF文件，solutions文件夹中则是angr的脚本，scaffold.py是我们做题人所需要补全的文件，里面的？？？ ...，都是待补全的，solve.py则是参考答案，但是实践下来发现里面的一些地址数据和脚本是有一些错误的。

具体练习的脚本都在文件夹里。

以下文章摘自：

[angr_ctf——从0学习angr（一）：angr简介与核心概念 - Uiharu - 博客园 (cnblogs.com)](https://www.cnblogs.com/level5uiharu/p/16925991.html)

[angr_ctf——从0学习angr（二）：状态操作和约束求解 - Uiharu - 博客园 (cnblogs.com)](https://www.cnblogs.com/level5uiharu/p/16932453.html)

[angr_ctf——从0学习angr（三）：Hook与路径爆炸 - Uiharu - 博客园 (cnblogs.com)](https://www.cnblogs.com/level5uiharu/p/16935854.html)



--------------------------------------------------------------------------------------------------------------------------------------------------------

### 二.Angr核心概念

##### **1.顶层接口**

​      Project类是angr的主类，也是angr的开始，通过初始化该类的对象，可以将你想要分析的二进制文件加载进来，就像这样：

> ```python
> import angr
> p = angr.Project('/bin/true')
> ```

​        参数为待分析的文件路径，它是唯一必须传入的参数，此外还有一个比较常用的参数load-options，它指明加载的方式，如下：

![image-20241005175231237](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20241005175231237.png)

​          使用angr时最重要的就是效率问题，少加载一些无关结果的库能够提升angr的效率，如下：

> ```python
> import angr
> p = angr.Project('/bin/true', auto_load_libs=False)
> ```

​          任何附加的参数都会被传递到angr的加载器，即CLE.loader中（CLE 即 CLE Loads Everything的缩写）

Project类中有许多方法和属性，例如加载的文件名、架构、程序入口点、大小端等等：

> ```python
> >>> print(p.arch, hex(p.entry), p.filename, p.arch.bits, p.arch.memory_endness )
> <Arch AMD64 (LE)> 0x4023c0 /bin/true 64 Iend_LE
> ```



##### **2.状态State**

​       Project实际上只是将二进制文件加载进来了，要执行它，实际上是对SimState对象进行操作，它是程序的状态。用docker来比喻，Project相当于开发环境，State则是使用开发环境制作的镜像。

​        要创建状态，需要使用Project对象中的factory，它还可以用于创建模拟管理器和基本块（后面提到），如下：

> ```python
> init_state = p.factory.entry_state()
> ```

预设状态有四种方式如下：

![image-20241005182631950](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20241005182631950.png)

​        状态包含了程序运行时的一切信息，寄存器、内存的值、文件系统以及**符号变量**等，这些信息的使用等用到时再进一步说明。

​         entry_state和blank_state是常用的两种方式，后者通常用于跳过一些极大降低angr效率的指令，它们间的对比如下：

> ```python
> >>> state = p.factory.entry_state()
> >>> print(state.regs.rax, state.regs.rip)
> <BV64 0x1c> <BV64 0x4023c0>
> ```

> ```python
> >>> state = p.factory.blank_state(addr=0x4023c0)
> >>> print(state.regs.rax, state.regs.rip)
> <BV64 reg_rax_42_64{UNINITIALIZED}> <BV64 0x4023c0>
> ```

​        在blank_state方式中，我们仍将地址设定为程序的入口点，然而rax中的值由于没有初始化，它现在是一个名字，也即符号变量，这是符号执行的基础，后续在细说。

​       此外，可以看到寄存器中的数据类型并不是int，而是BV64，它是一个位向量（Bit Vector），有关位向量的细节之后再说。



##### **3.模拟管理器（Simulation Manager）**

​         上述方式只是预设了程序开始分析时的状态，我们要分析程序就必须要让它到达下一个状态，这就需要模拟管理器的帮助（简称SM）.

​        使用以下指令能创建一个SM，它需要传入一个state或者state的列表作为参数：

> ```python
> simgr  = p.factory.simgr(state)
> ```

SM中有许多列表，这些列表被称为stash，它保存了处于某种状态的state，stash有如下几种：

![image-20241005183019790](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/image-20241005183019790.png)

​       默认情况下，state会被存放在active中。

stash中的state可以通过move()方法来转移，将fulter_func筛选出来的state从from_stash转移到to_stash：

> ```python
> simgr.move(from_stash='deadended', to_stash='more_then_50', filter_func=lambda s: '100' in s.posix.dumps(1))
> ```

​        stash是一个列表，可以使用python支持的方式去遍历其中的元素，也可以使用常见的列表操作。但angr提供了一种更高级的方式，在stash名字前加上one_，可以得到stash中的第一个状态，加上mp_，可以得到一个mulpyplexed版本的stash。

此外，稍微解释一下上面代码中的posix.dumps：

> - state.posix.dumps(0):表示到达当前状态所对应的程序输入
> - state.posix.dumps(1):表示到达当前状态所对应的程序输出

上述代码就是将deadended中输出的字符串包含'100'的state转移到more_then_50这个stash中。





 可以通过step()方法来让处于active的state执行一个基本块，这种操作不会改变state本身：

> >>> state = p.factory.entry_state()
> >>> simgr = p.factory.simgr(state)
> >>> print(state.regs.rax, state.regs.rip)
> >>> <BV64 0x1c> <BV64 0x4023c0>
>
> >>> print(simgr.one_active)
> >>> <SimState @ 0x4023c0>
>
> >>> simgr.step()
> >>> <SimulationManager with 1 active>
> >>> print(simgr.one_active)
> >>> <SimState @ 0x529240>
>
> >>> print(state.regs.rax, state.regs.rip)
> >>> <BV64 0x1c> <BV64 0x4023c0>

最后也是SM最常用的技术：探索技术（explorer techniques）

可以使用explorer方法去执行某个状态，直到找到目标指令或者active中没有状态为止，它有如下参数：

> - find：传入目标指令的地址或地址列表，或者一个用于判断的函数，函数以state为形参，返回布尔值
> - avoid：传入要避免的指令的地址或地址列表，或者一个用于判断的函数，用于减少路径

此外还有一些搜索策略，之后会集中讲解，默认使用DFS（深度优先搜索）。

explorer找到的符合find的状态会被保存在simgr.found这个列表当中，可以遍历其中元素获取状态。



##### **4.符号执行**

​      angr作为一个二进制分析的工具包，但它通常作为符号执行工具更为出名。

​      符号执行就是给程序传递一个符号而不是具体的值，让这个符号伴随程序运行，当碰见分支时，符号会进入哪个分支呢？

​      angr的回答是全都进入！angr会保存所有分支，以及分支后的所有分支，并且在分支时，保存进入该分支时的判断条件，通常这些判断条件时对符号的约束。

​       当angr运行到目标状态时，就可以调用求解器对一路上收集到的约束进行求解，最终得到某个符号能够到达当前状态的值。

​       例如，程序接收一个int类型的输入，当这个输入大于0小于5时，就会执行某条保存在该程序中，我们希望执行的指令（例如一个后门函数backdoor），具体而言如下图所示：

![img](https://nshide.oss-cn-hangzhou.aliyuncs.com/img_temp/3031561-20221129171743462-301356444.png)

​        angr会沿着分支按照某种策略（默认DFS）进行状态搜索，当达到目标状态（也就是backdoor能够执行的状态），此时angr已经收集了两个约束（x>0 以及x<=5），那么angr就通过这两个约束对x进行求解，解出来的x值就是能够让程序执行backdoor的输入。

​       在复杂的程序当中，从一个符号到backdoor的路径可能十分复杂，甚至包含一些加密解密的过程，这时就是angr大显身手的时候了。



##### **5.寄存器访问**

可以通过**state.regs.寄存器名**来访问和修改寄存器

> ```python
> >>> print(state.regs.eax, state.regs.ebx)
> <BV32 0x1c> <BV32 0x0>
> >>> state.regs.eax +=1
> >>> print(state.regs.eax, state.regs.ebx)
> <BV32 0x1d> <BV32 0x0>
> ```



##### **6.栈访问**

栈访问涉及两个寄存器：ebp和esp，以及两个指令：push和pop，对于寄存器的访问与其他寄存器相同

push和pop指令可以通过以下方法调用

> ```python
> state.stack_push(value)
> state.stack_pop()
> ```



##### **6.内存访问**

使用以下两个指令对内存读写：

**读内存-state.memory.load(addr, size,endness)**

**写内存-state.memory.store(data,size,endness)**

endness是指使用的大小端，通常应该和程序使用的大小端保持相同，而程序所使用的大小端可以用p.arch.memory_endness查询，因此在对默认值没有把握时，请让**endness=p.arch.memory_endness**。

此外，上述两个函数的size的单位均为字节，示例如下：

> ```python
> >>> state.memory.store(0x4000,state.solver.BVV(0x0123456789,40))
> >>> print(state.memory.load(0x4001,2))
> <BV16 0x2345>
> ```

其中存入地址0x4000处的数据是一个位向量，之后会介绍。



##### **7.文件操作**

​       angr提供了一个SimFile类用来模拟文件，通过将SimFile对象插入到状态的文件系统中，在使用angr分析程序时就可以使用该文件

> ```python
> filename = 'test.txt'
> simfile = angr.storage.SimFile(name=filename, content=data, size=0x40)
> state.fs.insert(filename, simfile)
> ```

上述指令能创建一个SimFile对象，文件名为test.txt，内容为data，输入的内容长度为0x40，单位为字节

​      之后，使用state.fs.insert方法，将SimFile对象插入到状态的文件系统中，在模拟运行程序时就可以使用这个文件了。



##### **8.位向量**

​        对于内存、寄存器等进行操作时，不仅可以使用python的int，angr还提供了位向量（Bit Vector，BV）

​       位向量就是一串比特的序列，这于python中的int不同，例如python中的int提供了整数溢出上的包装。而位向量可以理解为CPU中使用的一串比特流，需要注意的是，angr封装的位向量有两个属性：值以及它的长度

我们先生成几个位向量：

> ```python
> >>> one = state.solver.BVV(1,64)
> >>> one_hundred = state.solver.BVV(100,64)
> >>> short_nine = state.solver.BVV(9,27)
> >>> print(one,one_hundred,short_nine)
> <BV64 0x1> <BV64 0x64> <BV27 0x9>
> ```

BVV能够生成一个位向量，第二个参数表示该位向量的长度，单位为bit

这些位向量相互之间能够进行运算，但参与运算的位向量的长度必须相同

> >>> print(short_nine+1)
> >>> <BV27 0xa>
> >>> print(one+one_hundred)
> >>> <BV64 0x65>
> >>> print(one+short_nine)
> >>> Traceback (most recent call last):
> >>> File "<stdin>", line 1, in <module>
> >>> File "/home/kali/angr/venv/lib/python3.9/site-packages/claripy/operations.py", line 50, in _op
> >>> raise ClaripyOperationError(msg)
> >>> claripy.errors.ClaripyOperationError: args' length must all be equal

可以看到，当长度不一样时，claripy会提示“length must all be equal”，同时我们也得知，位向量运算的底层模块时claripy，之后会继续说明claripy

如果一定要进行长度不相等位向量之间的运算，可以扩展位向量，使用**zero_extend**会用零扩展高位，而**sign_extend**会在此基础上带符号地进行扩展

> ```python
> >>> print(one+short_nine.zero_extend(64-27))
> <BV64 0xa>
> ```

请注意zero_extend的参数是扩展多少位，而不是扩展到多少位

此外，位向量还可以之间与python的int进行运算：

> ```python
> >>> print(one+1,one*5)
> <BV64 0x2> <BV64 0x5>
> ```





接下来使用BVS（Bit Vectort Symbol）创建一些符号变量

> ```python
> >>> x = state.solver.BVS('x',64)
> >>> y = state.solver.BVS('y',64)
> >>> z = state.solver.BVS('notz',64)
> >>> print(x,y,z)
> <BV64 x_42_64> <BV64 y_43_64> <BV64 notz_44_64>
> ```

​        BVS的参数分别是符号变量名和长度，通过z的例子可以看到，BVS中符号变量名参数会影响位向量的名称，但这与你在angr脚本中使用这个符号变量的变量（也就是z）无关。

此时对符号变量进行运算，做比较判断，都不会得到一个具体的值，而是将这些操作统统保存到符号变量中：

> \>>> print(x+1)
>
> <BV64 x_42_64 + 0x1>



##### **9.符号约束与求解**

**a.符号约束**

​        每个符号变量本质上可以看做是一颗抽象语法树（AST），之前单独生成的符号变量<BV64 x_42_64>可以看作是只有一层的AST，对它进行操作实际上是在扩展AST，这样的AST的构造规则如下：

> - 如果AST只有根节点的话，那么它必定是符号变量或位向量
> - 如果AST有多层，那么叶子节点为符号变量和位向量，其他节点为运算符

其中一个节点的左右孩子可以使用args来访问，节点本身存放的信息则使用op来访问。可以通过下面的例子来理解：

> >>> ast = (x+5)*(y-1)
> >>> print(ast)
> >>> <BV64 (x_45_64 + 0x5) * (y_43_64 - 0x1)>
>
> >>> print(ast.op)
> >>> __mul__
>
> >>> print(ast.args)
> >>> (<BV64 x_45_64 + 0x5>, <BV64 y_43_64 - 0x1>)
>
> >>> print(ast.args[0].op)
> >>> __add__>>> print(ast.args[0].args[0])
> >>> <BV64 x_45_64>>>> print(ast.args[0].args[1])
> >>> <BV64 0x5>>>> print(ast.args[0].args[1].op)
> >>> BVV>>> print(ast.args[0].args[1].args)
> >>> (5, 64)>>> print(ast.args[0].args[0].args)
> >>> ('x_45_64', None, None, None, False, False, None)>>> print(ast.args[0].args[0].op)BVS

可以发现，对单独的节点取op的话，可以得到它的类型（示例中为BVV和BVS）

之前我们使用BVS创建了符号变量，现在如果对该符号变量进行比较判断操作，会得到如下结果：

> ```python
> >>> print(x>0)
> <Bool x_42_64 > 0x0>
> ```

它现在不是一个位向量了，而是一个符号化的布尔类型

这些布尔类型的值可以通过**is_true**和**is_false**来判断，但对于上述有符号变量参与的布尔类型，它永远为false

> ```python
> >>> print(state.solver.is_true(x>0))
> False
> >>> print(state.solver.is_false(x>0))
> False
> ```

此外需要注意的是，直接使用比较符号比较两个位向量，通常是默认不带符号的，例子如下：

> >>> mfive = state.solver.BVV(-5,64)
> >>> one = state.solver.BVV(1,64)
> >>> print(one>mfive)
> >>> <Bool False>
> >>> print(mfive)
> >>> <BV64 0xfffffffffffffffb>
> >>> print(state.solver.is_true(one>mfive))
> >>> False

-5在内存中以0xfffffffffffffffb存储，作为无符号数，它比1要大



​       符号约束是一个和状态相关的概念，或者说一个state除了包含内存、寄存器中的值这些信息外，还包含了符号约束，也就是要到达当前状态符号变量所必须满足的条件。

除了运行程序，SM根据分支收集起来的符号约束之外，也可以自行手动添加约束：

> >>> print(x,y)
> >>> <BV64 x_45_64> <BV64 y_43_64>
> >>> state.solver.add(x>y)
> >>> [<Bool x_45_64 > y_43_64>]
> >>> state.solver.add(x>5)
> >>> [<Bool x_45_64 > 0x5>]
> >>> state.solver.add(x<8)
> >>> [<Bool x_45_64 < 0x8>]

此时，x必须满足大于5小于8，而y必须满足小于x。





**b.符号求解**

可以使用state.solver.eval(x)来求解当前状态（即state）中的符号约束下，x的值

> ```python
> >>> state.solver.eval(x)
> 6
> ```

求解完x之后，此时如果求解y，则会得到之前求解结果条件下的y，也就是说，y此时必定小于6

此外，很明显能够看到，x应该是有多个值的，可以solver中的其他方法取出来：

> - solver.eval(x):给出表达式的一个可能解
> - sovler.eval_one(x):给出表达式的解，如果有多个解，将抛出错误
> - solver.eval_upto(x,n)给出表达式的至多n个解
> - sovler.eval_taleast(x,n):给出表达式的n个解，如果解的数量少于n，则抛出错误
> - solver.eval_exact(x,n):给出表达式的n个解，如果解的个数不为n，则抛出错误
> - sovler.min(x):给出表达式的最小解
> - sovler.max(x):给出表达式的最大解

这些方法还有两个可省略的参数：

> - extra_constraints：可以作为约束进行求解，但不会被添加到当前状态
>
> - cast_to：将传递结果转换成指定数据类型，目前只能是int和bytes，例如
>
> - ```
>   state.solver.eval(state.solver.BVV(0x41424344, 32), cast_to=bytes)` 将返回`b'ABCD'
>   ```

​       此外，如果将两个互相矛盾的约束加入到一个state当中，那么这个state就会被放到unsat这个stash里面，对这样的state进行求解会导致异常，可以使用**state.satisfiable()**来检查是否有解

​        加入到状态中的约束在进行约束求解时的关系是“与”的关系，也就是说必须都得满足，那么如果有其他的关系，比如或之类的关系，该如何表示呢？

​        事实上，根本不会存在或这样的约束之间的关系，因为angr保存所有分支，因此到达某个状态的条件必然是一层一层都满足的情况下到达的，如果在条件判断时有“或”这样的关系存在，那么这样的解将会出现在另一个state当中，而另一个state当中的符号约束之间也必然都是“与”的关系。

