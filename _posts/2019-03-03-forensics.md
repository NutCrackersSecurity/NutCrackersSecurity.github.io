---
layout: post
title: "Volatility: Extract Password from RAM"
date: 2019-03-03 20:11:00 -0500
categories: forensics
tags: windows forensics
image:
  path: /assets/img/headers/forensics/forensics.jpg
---

## Volatility: Extract Password from RAM

Hello everyone. Today's topic will be volatility: Extract Password from RAM, as well as information about Windows 7 SP1x86 via Volatility Framework. This notion came from a University Professor who remarked something interesting: RAM can store information while ROM is used for reading. Remember that, in contrast to non-volatile memory, volatile memory is computer memory that requires electricity to maintain the recorded information. It holds its contents while switched on, but when the power is interrupted, the stored data is quickly lost.

Perhaps you are wondering what this volatility framework is and what it is used for. Volatility is a free and open source software tool that analyzes RAM (Random Access Memory) in 32 and 64 bit computers. It can analyze Linux, Windows, Mac, and Android systems. It is Python-based and may be operated on Windows, Linux, and Mac computers. It is capable of analyzing raw dumps, crash dumps, VMware dumps (.vmem), virtual box dumps, and many other types of data.

The first step is to obtain a RAM dump from Windows. I made advantage of [Dumpit](https://qpdownload.com/dumpit/?fbclid=IwAR1l_gJfhfCjOc7rUhXXJCXg3UvU79IZaJkFD63DyJjt2exABKoRo0MgrSQ).

![forensics](/assets/img/headers/forensics/forensics1.png)

Installing Volatility Framework is necessary in order to analyze this raw file. Installing requires the following: You must install the following packages and dependencies in order to install this framework on Linux. The following recommended packages for Linux may require you to install a few other packages or libraries as prerequisites. 
```sh
sudo apt-get install pcregrep libpcre++-dev python-dev -y 
```

- Distorm3 - Powerful Disassembler Library For x86/AMD64.
- Yara - A malware identification and classification tool.
- Pycrypto -  The Python Cryptography Toolkit.

I therefore decide to create a small bash script to install this program. Find this  here [https://github.com/T3jv1l/Volatility-Installer](https://github.com/T3jv1l/Volatility-Installer).

![forensics](/assets/img/headers/forensics/forensics2.png)

![forensics](/assets/img/headers/forensics/forensics3.png)

![forensics](/assets/img/headers/forensics/forensics4.png)

In order to use Volatility for analysis, we must first set up a profile that informs Volatility of the operating system the dump was created on, such as Windows 7, Linux, or Mac OS.
```sh
 ./vol.py imageino –f "Destination of the memory Dump"
```
![forensics](/assets/img/headers/forensics/forensics5.png)

As can be seen, Volatility advises using the `Win7SP0x86` and `Win7SP1x86` profiles.

It's time to use `--profile=Win7SP1x86` and hivelist to find the entire paths to the matching hive on disk as well as the virtual addresses of registry hives in memory. Visit [https://docs.microsoft.com/en-us/windows/desktop/sysinfo/registry-hives](https://docs.microsoft.com/en-us/windows/desktop/sysinfo/registry-hives) for additional information about Registry Hives.

![forensics](/assets/img/headers/forensics/forensics6.png)

What do we have? If it's clear, we search for a virtual address. Why did I select SAM in `%SystemRoot%/system32/config/SAM`? Due to the fact that user passwords are kept in a registry hive in a hashed format, either as an LM hash or an NTLM hash. This file is mounted on HKLM/SAM and may be located in `%SystemRoot%/system32/config/SAM`. This is the value `0x96754008`.

Inside the registry key `HKLM\SYSTEM\CurrentControlSet\Control\hivelist` is the Registry Machine System.The registry tree holds data for managing device settings and various aspects of system initialization. This is `0x8ac1c008`.

Today, we obtain credentials using hashdump.To use hashdump, enter the virtual addresses of the SYSTEM and SAM hives as `-y` and `-s`, respectively, as follows:

![forensics](/assets/img/headers/forensics/forensics7.png)

Boom we have a credentials about password , i made a little video about this technique, you can found here : [https://youtu.be/YVv2B4D_ysg](https://youtu.be/YVv2B4D_ysg).

![forensics](/assets/img/headers/forensics/forensics8.png)

Decrypt this hash.

![forensics](/assets/img/headers/forensics/forensics9.png)

I hope you like this article about Forensics and sorry for my bad English , i am not a native speaker (Happy Hack).

## Reference

[https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#hashdump](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#hashdump)

[https://resources.infosecinstitute.com/memory-forensics-and-analysis-using-volatility/?fbclid=IwAR1_po75pLlt5Yg_eJOtKtaR93-lgsi8SsoIaR6t832zAtPDCQf_zsuPrSE#gref](https://resources.infosecinstitute.com/memory-forensics-and-analysis-using-volatility/?fbclid=IwAR1_po75pLlt5Yg_eJOtKtaR93-lgsi8SsoIaR6t832zAtPDCQf_zsuPrSE#gref)

[https://www.andreafortuna.org/dfir/forensics/how-to-extract-a-ram-dump-from-a-running-virtualbox-machine/?fbclid=IwAR3V-48WZspdCtOPkqW8xpjMeG3o4rntOj4mDahVAfy5SoG5_hPJQCfwkPA](https://www.andreafortuna.org/dfir/forensics/how-to-extract-a-ram-dump-from-a-running-virtualbox-machine/?fbclid=IwAR3V-48WZspdCtOPkqW8xpjMeG3o4rntOj4mDahVAfy5SoG5_hPJQCfwkPA)

[https://github.com/T3jv1l/Volatility-Installer](https://github.com/T3jv1l/Volatility-Installer)
