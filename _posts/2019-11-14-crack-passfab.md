---
layout: post
title: "Cracking the PassFab RAR Software"
date: 2019-11-14 22:30:00 -0500
categories: reverse cracking
tags: windows reverse-engineering asm cracking
image:
  path: /assets/img/headers/crack-passfab/crack.png
---


## Cracking the PassFab RAR Software

Hello, my name is Moldovan Darius, also known as [@T3jv1l](https://twitter.com/T3jv1l). Here is a Proof of Concept that shows how I was able to break the PassFab software using the buffer overflow bug. I'll define buffer overflow vulnerability for the first time.

Buffer Overflow: The buffer serves as a temporary storage location for data. As a result of a change in memory caused by exceeding the initial storage allocation, extra data leak into other storage locations and may corrupt or replace the data they contain. Although this program can be exploited without endangering users, I was still able to steal all of the (Serial Keys) using this buffer.

Let's get our hands dirty: To disassemble the software and recreate each step, we need a few tools. For static analysis, I use IDA PRO 6.8 Version, and for dynamic analysis, I use x64dbg. The first step is to load a program in x64dbg, which is simple to do (press `ALT+A` to connect the program). Run as administrator on x64dbg because PassFab only works with this privilege.

![crack](/assets/img/headers/crack-passfab/crack1.png)

The software has been attached. Because this software has ASLR [Address Stack Layer Randomize](https://en.wikipedia.org/wiki/Address_space_layout_randomization) protection enabled, which means the address is always changing, we need to get the hex address, for example, 0x01234567, where the passfab.exe program starts. All of the addresses in the IDA Tools are reconfigured using this address, where passfab starts. Now that you've viewed the memory map using `ALT+M`, scroll down till you see something similar.

![crack](/assets/img/headers/crack-passfab/crack2.png)

Copy the initial address `0x00320000`, ASLR may cause you to see a different address, but the idea is the same.

It's time to Rebase program the memory from IDA, which implies that the entire program will be shifted by the designated numbers of bytes. `Edit > Segments > Rebase program` is the first step for rebasing an address in IDA. Start address at passfab.exe is the value we need.

![crack](/assets/img/headers/crack-passfab/crack3.png)

It's now our turn to identify software with poor coding. Sending `0x41` (A) into the `Licensed E-mail` and `Registration Code` fields will cause a buffer exceed, which is what we need. To produce 2000 A characters, I wrote an easy Python program.
```python
#!/usr/bin/Python

  filename="crack.txt"
  junk="\x41"*2000

  buffer = junk
  textfile = open(filename, 'w')
  textfile.write(buffer)
  textfile.close()
```
Send our A into the application.

![crack](/assets/img/headers/crack-passfab/crack4.png)

Look at the EAX register in x64dgb, if it has AAAA overwritten, the memory has been overwritten with my character.

![crack](/assets/img/headers/crack-passfab/crack5.png)

The essential register, EIP, is where we need to concentrate right now. He tried to explain what was wrong with this program there. Go to IDA and copy the EIP address `0x00364800`. In IDA, press `G` to copy the EIP address.

![crack](/assets/img/headers/crack-passfab/crack6.png)

We now have this capability. To translate ASM into pseudocode and view the code, press `F5`.

![crack](/assets/img/headers/crack-passfab/crack7.png)

The function is translated in pseudocode.

![crack](/assets/img/headers/crack-passfab/crack8.png)

Let me briefly describe what took place. The technique for producing the offline key is formed with the data that the user enters, and this function compares the serial key. This section compares validation:

![crack](/assets/img/headers/crack-passfab/crack9.png)

There we have the variable `v50`, which is a char, that means there is the key for validation. Let’s look close `char v50;//`  is located in `bp-110h`.

![crack](/assets/img/headers/crack-passfab/hmm.png)

So if we analyze the address of `bp-110H` will see something interesting.

![crack](/assets/img/headers/crack-passfab/crack11.png)

The `0x003647E8 lea edi, [esp+46Ch+var_110]` is the key that is moved into the EDI register, and it can be found in Section 1. We have more instructions in Section 2, `CMP` is used for compare and `JNZ` functions as the C/C++ equivalent of the "if" instruction. This means that Section 2 is more comparable to a serial key validation procedure.

The next step is to utilize PassFab RAR in x64dbg once more and set a breakpoint at `var_110`. Discover the address, then set a breakpoint using `F2`.

![crack](/assets/img/headers/crack-passfab/crack12.png)

Run the software once more and enter the fictitious email address test@test along with the serial number "test" to check the index source register (ESI).

![crack](/assets/img/headers/crack-passfab/crack13.png)

The first serial key (Pro Personal RAR Password Recovery: ESI: `98AA05-858868-AE5EF0-E1432D-24CFA107`) is now available in the debugger after clicking the Register bottom.

![crack](/assets/img/headers/crack-passfab/crack14.png)

You can see in the debbugger that he attempted to match the original key with my "test" fake key.

![crack](/assets/img/headers/crack-passfab/crack15.png)

We must now rerun the software in order to view the new Serial Keys (Pro Family RAR Password). The final set of serial keys is Pro Unlimited RAR Password.

The final key to be tested is `98AA05-808376-B45CF7-F44A1B-37DCA336`.

![crack](/assets/img/headers/crack-passfab/crack16.png)

![crack](/assets/img/headers/crack-passfab/crack17.png)

I hope you like to read about this topic Reverse Engineering Stuff and Exploit Development. By the way Softwares affected : PassFab for PDF, PassFab for RAR and PassFab for ZIP.

## Reference

[https://www.hex-rays.com/products/ida/](https://www.hex-rays.com/products/ida/)

[https://github.com/x64dbg/x64dbg/releases](https://github.com/x64dbg/x64dbg/releases)

[https://resources.infosecinstitute.com/applied-cracking-byte-patching-ida-pro/#gref](https://resources.infosecinstitute.com/applied-cracking-byte-patching-ida-pro/#gref)
