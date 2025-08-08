---
title: 浅谈 Linux 系统下 proc 文件系统内容
tags: [Android, Linux]
categories: 其他
---

# 浅谈 Linux 系统下 proc 文件系统内容

### 一、内容摘要

Linux 系统上的 /proc 目录是一种文件系统，即 proc 文件系统



### 二、开始

​        Linux 系统上的 /proc 目录是一种文件系统，即 proc 文件系统。与其他常见的文件系统不同的是，/proc 是一种伪文件系统（也即虚拟文件系统），存储的是当前内核运行状态的一系列特殊文件，用户可以通过这些文件查看有关系统硬件及当前正在运行进程的信息，甚至可以通过更改其中某些文件来改变内核的运行状态。

​        基于 /proc 文件系统如上所述的特殊性，其内的文件也常被称作虚拟文件，并具有一些独特的特点。例如，其中有些文件虽然使用查看命令查看时会返回大量信息，但文件本身的大小却会显示为 0 字节。此外，这些特殊文件中大多数文件的时间以及日期属性通常为当前系统时间和日期，这跟它们随时会被刷新（存储于 RAM 中）有关。

​        为了查看以及使用上的方便，这些文件通常会按照相关性进行分类存储于不同的目录甚至子目录中，如 /proc/scsi 目录中存储的就是当前系统上所有 SCSI 设备的相关信息，/proc/N 中存储的则是系统当前正在运行的进程和相关信息，其中 N 为正在运行的进程（可以想象得到，在某进程结束后其相关目录则会消失）。

​        大多数虚拟文件可以使用文件查看命令如 cat、more 或者 less 进行查看，有些文件信息表述的内容可以一目了然，但也有文件的信息却不怎么具有可读性。不过，这些可读性较差的文件在使用一些命令如 apm、free、lspci 或 top 查看时却可以有着不错的表现。



#### 一、进程目录中的常见文件介绍

​       /proc目录中包含许多**以数字命名**的子目录，这些数字表示系统当前正在运行进程的进程号，里面包含对应进程相关的多个信息文件。

```shell
┌──(root㉿NshIdE)-[/home/nshide-kali]
└─# ll /proc
total 0
dr-xr-xr-x  9 root        root                      0 Jul 24 17:35 1
dr-xr-xr-x  9 root        root                      0 Jul 24 17:35 10
dr-xr-xr-x  9 root        root                      0 Jul 24 17:35 13
dr-xr-xr-x  9 root        root                      0 Jul 24 17:35 14
dr-xr-xr-x  9 nshide-kali nshide-kali               0 Jul 24 17:35 15
dr-xr-xr-x  9 root        root                      0 Jul 24 17:35 31
dr-xr-xr-x  9 root        root                      0 Jul 24 17:35 35
dr-xr-xr-x  9 root        root                      0 Jul 24 17:35 36
dr-xr-xr-x  9 root        root                      0 Jul 24 17:35 38
dr-xr-xr-x  9 root        root                      0 Jul 24 17:35 41
```

上面列出的是 /proc 目录中一些进程相关的目录，每个目录是对应进程相关信息的文件。下面是作者系统（Kali）上运行的一个 PID 为 38 的进程 saslauthd 的相关文件，其中有些文件是每个进程都会具有的，后文会对这些常见文件做出说明。

```shell
┌──(root㉿NshIdE)-[/home/nshide-kali]
└─# ll /proc/38
total 0
-r--r--r--  1 root root 0 Jul 24 17:38 arch_status
dr-xr-xr-x  2 root root 0 Jul 24 17:38 attr
-r--------  1 root root 0 Jul 24 17:38 auxv
-r--r--r--  1 root root 0 Jul 24 17:38 cgroup
--w-------  1 root root 0 Jul 24 17:38 clear_refs
-r--r--r--  1 root root 0 Jul 24 17:38 cmdline
-rw-r--r--  1 root root 0 Jul 24 17:38 comm
-rw-r--r--  1 root root 0 Jul 24 17:38 coredump_filter
-r--r--r--  1 root root 0 Jul 24 17:38 cpuset
lrwxrwxrwx  1 root root 0 Jul 24 17:38 cwd -> /home/nshide-kali
-r--------  1 root root 0 Jul 24 17:38 environ
lrwxrwxrwx  1 root root 0 Jul 24 17:38 exe -> /usr/bin/bash
dr-x------  2 root root 0 Jul 24 17:38 fd
dr-xr-xr-x  2 root root 0 Jul 24 17:38 fdinfo
-rw-r--r--  1 root root 0 Jul 24 17:38 gid_map
-r--------  1 root root 0 Jul 24 17:38 io
-r--r--r--  1 root root 0 Jul 24 17:38 limits
-rw-r--r--  1 root root 0 Jul 24 17:38 loginuid
dr-x------  2 root root 0 Jul 24 17:38 map_files
-r--r--r--  1 root root 0 Jul 24 17:38 maps
-rw-------  1 root root 0 Jul 24 17:38 mem
-r--r--r--  1 root root 0 Jul 24 17:38 mountinfo
-r--r--r--  1 root root 0 Jul 24 17:38 mounts
-r--------  1 root root 0 Jul 24 17:38 mountstats
dr-xr-xr-x 65 root root 0 Jul 24 17:38 net
dr-x--x--x  2 root root 0 Jul 24 17:38 ns
-rw-r--r--  1 root root 0 Jul 24 17:38 oom_adj
-r--r--r--  1 root root 0 Jul 24 17:38 oom_score
-rw-r--r--  1 root root 0 Jul 24 17:38 oom_score_adj
-r--------  1 root root 0 Jul 24 17:38 pagemap
-r--------  1 root root 0 Jul 24 17:38 personality
-rw-r--r--  1 root root 0 Jul 24 17:38 projid_map
lrwxrwxrwx  1 root root 0 Jul 24 17:38 root -> /
-rw-r--r--  1 root root 0 Jul 24 17:38 sched
-r--r--r--  1 root root 0 Jul 24 17:38 schedstat
-r--r--r--  1 root root 0 Jul 24 17:38 sessionid
-rw-r--r--  1 root root 0 Jul 24 17:38 setgroups
-r--r--r--  1 root root 0 Jul 24 17:38 smaps
-r--r--r--  1 root root 0 Jul 24 17:38 smaps_rollup
-r--------  1 root root 0 Jul 24 17:38 stack
-r--r--r--  1 root root 0 Jul 24 17:38 stat
-r--r--r--  1 root root 0 Jul 24 17:38 statm
-r--r--r--  1 root root 0 Jul 24 17:38 status
-r--------  1 root root 0 Jul 24 17:38 syscall
dr-xr-xr-x  3 root root 0 Jul 24 17:38 task
-rw-r--r--  1 root root 0 Jul 24 17:38 timens_offsets
-r--r--r--  1 root root 0 Jul 24 17:38 timers
-rw-rw-rw-  1 root root 0 Jul 24 17:38 timerslack_ns
-rw-r--r--  1 root root 0 Jul 24 17:38 uid_map
-r--r--r--  1 root root 0 Jul 24 17:38 wchan
```



##### 1.01 cmdline

- 启动当前进程的完整命令，但僵尸进程目录中的此文件不包含任何信息

```shell
┌──(root㉿NshIdE)-[/home/nshide-kali]
└─# more /proc/38/cmdline
bash
```



##### 1.02 cwd

- 指当前进程运行目录的一个符号链接



##### 1.03 environ

- 当前进程的环境变量列表，彼此间用空字符（NULL）隔开；变量用大写字母表示，其值用小写字母表示



##### 1.04 exe

- 指向启动当前进程的可执行文件（完整路径）的符号链接，通过 /proc/N/exe 可以启动当前进程的一个拷贝



##### 1.05 fd

- 这是个目录，包含当前进程打开的每一个文件的文件描述符（file descriptor），这些文件描述符是指向实际文件的一个符号链接



##### 1.06 limits

- 当前进程所使用的每一个受限资源的软限制、硬限制和管理单元；此文件仅可由实际启动当前进程的UID用户读取



##### 1.07 maps

- 当前进程关联到的每个可执行文件和库文件在内存中的映射区域及其访问权限所组成的列表



##### 1.08 mem

- 当前进程所占用的内存空间，由open、read和lseek等系统调用使用，不能被用户读取



##### 1.09 root

- 指向当前进程运行根目录的符号链接(即当前进程所看到的“根目录”（/）是什么)；在Unix和Linux系统上，通常采用chroot命令使每个进程运行于独立的根目录



##### 1.10 stat

- 当前进程的状态信息，包含一系列格式化后的数据列，可读性差，通常由 ps 命令使用



##### 1.11 statm

- 当前进程占用内存的状态信息，通常以“页面”(page)表示



##### 1.20 status

- 与 stat 所提供信息类似，但可读性较好，每行表示一个属性信息；其详细介绍请参见 proc 的 man 手册页



##### 1.21 task

- 目录文件，包含由当前进程所运行的每一个线程的相关信息，每一个线程的相关信息文件均保存在一个由线程号(TID)命名的目录中



#### 二、/proc 目录下常见的文件介绍

##### 2.01 /proc/apm

- 高级电源管理(APM)版本信息以及电池相关状态信息，通常由 apm 命令使用



##### 2.02 /proc/buddyinfo

- 用于诊断内存碎片问题的相关信息文件



##### 2.03 /proc/cmdline

- 在启动时传递至内核的相关参数信息，这些信息通常由 lilo 或 grub 等启动管理工具进行传递



##### 2.04 /proc/cpuinfo

- 处理器相关信息文件



##### 2.05 /proc/crypto

- 系统上已安装的内核使用的密码算法以及每个算法的详细信息列表



##### 2.06 /proc/devices

- 系统已经加载的所有设备和字符设备的信息，包含主设备号和设备组(与主设备号对应的设备类型)



##### 2.07 /proc/diskstats

- 每块磁盘设备的磁盘 I/O 统计信息列表



##### 2.08 /proc/dma

- 每个正在使用且注册的 ISA DMA 通道的信息列表



##### 2.09 /proc/execdomains

- 内核当前支持的执行域(每种操作系统独特“个性”)信息列表



##### 2.10 /proc/fb

- 帧缓冲设备列表文件，包含帧缓冲设备的设备号和相关驱动信息



##### 2.11 /proc/filesystems

- 当前被内核支持的文件系统类型列表文件，被表示为 nodev 的文件系统表示不需要块设备的支持；通常 mount 一个设备时，如果没有指定文件系统类型将通过此文件来决定其所需文件系统的类型



##### 2.12 /proc/interrupts

- x86 或者 x86_64 体系架构系统上每个 IRQ 相关的中断号列表；多路处理器平台上每个 CPU  对于每个 I/O 设备均有自己的中断号



##### 2.13 /proc/iomen

- 每个物理设备上的记忆体(RAM 或者 ROM)在系统内存中的映射信息



##### 2.14 /proc/ioports

- 当前正在使用且已经注册过的与物理设备进行通讯的输入-输出端口范围信息列表



##### 2.15 /proc/kallsyms

- 模块管理工具，用来动态链接或者绑定可装载模块的符号定义，由内核输出；(内核 2.5.71 以后的版本支持此功能)；通常这个文件中的信息量相当大



##### 2.16 /proc/kcore

- 系统使用的物理内存，以 ELF 核心文件(core file) 格式存储，其文件大小为已使用的物理内存(RAM)加上 4KB；这个文件用来检查内核数据结构当前状态，因此，通常由 GDB 调试工具使用，但不能使用文件查看命令打开此文件



##### 2.17 /proc/kmsg

- 此文件用来保存由内核输出的信息，通常由 /sbin/klogd 或者 bin/dmsg 等程序使用，不要试图使用查看命令打开此文件



##### 2.18 /proc/loadavg

保存关于 CPU 和磁盘 I/O 的负载平均值，其前三列分别表示每1秒钟、每5秒钟以及每15秒钟的负载平均值，类似于 uptime 命令输出的相关信息；第四列是由斜线隔开的两个数值，前者表示当前正由内核调度的实体(进程和线程)的数目，后者表示系统当前存活的内核调度实体的数目；第五列表示此文件被查看前最近一个内核创建的进程PID



##### 2.19 /proc/locks

- 保存当前由内核锁定的文件的相关信息，包含内核内部的调试数据；每个锁定占据一行，且具有一个唯一的编号；如下输出信息中每行的第二列表示当前锁定使用的锁定类别，POSIX表示目前较新类型的文件锁，由lockf系统调用产生，FLOCK是传统的UNIX文件锁，由flock系统调用产生；第三列也通常由两种类型，ADVISORY表示不允许其他用户锁定此文件，但允许读取，MANDATORY表示此文件锁定期间不允许其他用户任何形式的访问；

```shell
[root@rhel5 ~]# more /proc/locks
1: POSIX  ADVISORY  WRITE 4904 fd:00:4325393 0 EOF
2: POSIX  ADVISORY  WRITE 4550 fd:00:2066539 0 EOF
3: FLOCK  ADVISORY  WRITE 4497 fd:00:2066533 0 EOF
```



##### 2.20 /proc/mdstat

- 保存RAID相关的多块磁盘的当前状态信息，在没有使用RAID机器上，其显示为如下状态：

  ```shell
  [root@rhel5 ~]# less /proc/mdstat
  Personalities :
  unused devices: <none>
  ```



##### 2.21 /proc/meminfo

- 系统中关于当前内存的利用状况等的信息，常由free命令使用；可以使用文件查看命令直接读取此文件，其内容显示为两列，前者为统计属性，后者为对应的值

  ```shell
  [root@rhel5 ~]# less /proc/meminfo
  MemTotal:       515492 kB
  MemFree:          8452 kB
  Buffers:         19724 kB
  Cached:         376400 kB
  SwapCached:          4 kB
  …………
  ```



##### 2.22 /proc/mounts

- 在内核2.4.29版本以前，此文件的内容为系统当前挂载的所有文件系统，在2.4.19以后的内核中引进了每个进程使用独立挂载名称空间的方式，此文件则随之变成了指向/proc/self/mounts（每个进程自身挂载名称空间中的所有挂载点列表）文件的符号链接；/proc/self是一个独特的目录，后文中会对此目录进行介绍

```shell
[root@rhel5 ~]# ll /proc |grep mounts
lrwxrwxrwx  1 root      root             11 Feb  8 06:43 mounts -> self/mounts
```

如下所示，其中第一列表示挂载的设备，第二列表示在当前目录树中的挂载点，第三点表示当前文件系统的类型，第四列表示挂载属性（ro或者rw），第五列和第六列用来匹配/etc/mtab文件中的转储（dump）属性

```shell
[root@rhel5 ~]# more /proc/mounts
rootfs / rootfs rw 0 0
/dev/root / ext3 rw,data=ordered 0 0
/dev /dev tmpfs rw 0 0
/proc /proc proc rw 0 0
/sys /sys sysfs rw 0 0
/proc/bus/usb /proc/bus/usb usbfs rw 0 0
…………
```



##### 2.23 /proc/modules

- 当前装入内核的所有模块名称列表，可以由lsmod命令使用，也可以直接查看；如下所示，其中第一列表示模块名，第二列表示此模块占用内存空间大小，第三列表示此模块有多少实例被装入，第四列表示此模块依赖于其它哪些模块，第五列表示此模块的装载状态（Live：已经装入；Loading：正在装入；Unloading：正在卸载），第六列表示此模块在内核内存（kernel memory）中的偏移量

```shell
[root@rhel5 ~]# more /proc/modules
autofs4 24517 2 - Live 0xe09f7000
hidp 23105 2 - Live 0xe0a06000
rfcomm 42457 0 - Live 0xe0ab3000
l2cap 29505 10 hidp,rfcomm, Live 0xe0aaa000
…………
```



##### 2.24 /proc/partitions

- 块设备每个分区的主设备号（major）和次设备号（minor）等信息，同时包括每个分区所包含的块（block）数目（如下面输出中第三列所示）

```shell
[root@rhel5 ~]# more /proc/partitions
major minor  #blocks  name

   8     0   20971520 sda
   8     1     104391 sda1
   8     2    6907950 sda2
   8     3    5630782 sda3
   8     4          1 sda4
   8     5    3582463 sda5
```



##### 2.25 /proc/pci

- 内核初始化时发现的所有PCI设备及其配置信息列表，其配置信息多为某PCI设备相关IRQ信息，可读性不高，可以用“/sbin/lspci –vb”命令获得较易理解的相关信息；在2.6内核以后，此文件已为/proc/bus/pci目录及其下的文件代替



##### 2.26 /proc/slabinfo

- 在内核中频繁使用的对象（如inode、dentry等）都有自己的cache，即slab pool，而/proc/slabinfo文件列出了这些对象相关slap的信息；详情可以参见内核文档中slapinfo的手册页



##### 2.27 /proc/stat

- 实时追踪自系统上次启动以来的多种统计信息；如下所示，其中，
  “**cpu**”行后的八个值分别表示以1/100（jiffies）秒为单位的统计值（包括系统运行于用户模式、低优先级用户模式，运系统模式、空闲模式、I/O等待模式的时间等）；
  “**intr**”行给出中断的信息，第一个为自系统启动以来，发生的所有的中断的次数；然后每个数对应一个特定的中断自系统启动以来所发生的次数；
  “**ctxt**”给出了自系统启动以来CPU发生的上下文交换的次数。
  “**btime**”给出了从系统启动到现在为止的时间，单位为秒；
  “**processes**“ (total_forks) 自系统启动以来所创建的任务的个数目；
  “**procs_running**”：当前运行队列的任务的数目；
  “**procs_blocked**”：当前被阻塞的任务的数目；



##### 2.28 /proc/swaps

- 当前系统上的交换分区及其空间利用信息，如果有多个交换分区的话，则会每个交换分区的信息分别存储于/proc/swap目录中的单独文件中，而其优先级数字越低，被使用到的可能性越大；下面是作者系统中只有一个交换分区时的输出信息



##### 2.29 /proc/uptime

- 系统上次启动以来的运行时间，如下所示，其第一个数字表示系统运行时间，第二个数字表示系统空闲时间，单位是秒

```shell
[root@rhel5 ~]# more /proc/uptime
3809.86 3714.13
```



##### 2.30 /proc/version

- 当前系统运行的内核版本号



##### 2.31 /proc/vmstat

- 当前系统虚拟内存的多种统计数据，信息量可能会比较大，这因系统而有所不同，可读性较好



##### 2.32 /proc/zoneinfo

- 内存区域（zone）的详细信息列表，信息量较大



#### 三、/proc/sys目录详解

​        与 /proc下其它文件的“只读”属性不同的是，管理员可对/proc/sys子目录中的许多文件内容进行修改以更改内核的运行特性，事先可以使用“ls -l”命令查看某文件是否“可写入”。写入操作通常使用类似于“echo DATA > /path/to/your/filename”的格式进行。需要注意的是，即使文件可写，其一般也不可以使用编辑器进行编辑。

##### 3.01 /proc/sys/debug子目录

- 此目录通常是一空目录



##### 3.02  /proc/sys/dev子目录

- 为系统上特殊设备提供参数信息文件的目录，其不同设备的信息文件分别存储于不同的子目录中，如大多数系统上都会具有的/proc/sys/dev /cdrom和/proc/sys/dev/raid（如果内核编译时开启了支持raid的功能） 目录，其内存储的通常是系统上cdrom和raid的相关参数信息文件。

