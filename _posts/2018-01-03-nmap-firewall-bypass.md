---
layout: post
title: "Nmap Firewall Bypass "
date: 2018-01-03 10:00:00 -0500
categories: networking
tags: linux nmap firewall
image:
  path: /assets/img/headers/nmap/2.jpg
---

Hello hackers! Today, we will demonstrate how to perform an Nmap firewall scan using Iptable rules and attempt to bypass the firewall filter to perform advanced NMAP scanning. Let's get started!

For this demonstration, I will be using Virtualbox to simulate the scan.

- Attacker's IP: 192.168.0.22 [Kali Linux]
- Target's IP: 192.168.0.19 [Ubuntu]

## TCP SCAN ANALYSIS:

To perform a TCP (-sT-) scan for open port enumeration, open the terminal in your Kali Linux and execute the following command:
```bash
nmap -sT -p 80 192.168.0.19
```
From the image below, you can observe that we have scanned port 80, and the result shows that Port 80 is open.
![scan](/assets/img/headers/nmap/1.png)


| Scan Name    | Flag             | Data Length | TTL              |
|--------------|------------------|-------------|------------------|
| -sT (TCP)    | SYN →            | 60          | 64               |
| -sS (Stealth)| SYN →            | 44          | <64 (Less than 64)|
| -sF (Finish) | FIN →            | 40          | <64 (Less than 64)|
| -sN (Null)   | NULL →           | 40          | <64 (Less than 64)|
| -sX (Xmas)   | FIN, PSH, URG →  | 40          | <64 (Less than 64)|

## Reject SYN Flag with IPTables

To enhance network security, administrators often employ firewall filters to hinder attackers from performing TCP scans and disrupt the three-way handshake communication. One effective method is to reject SYN packets using IPTables.

To block SYN packets in Ubuntu and prevent TCP scans, execute the following command:
```sh
iptables -I INPUT -p tcp --tcp-flags ALL SYN -j REJECT --reject-with tcp-reset
```
IPTables functions as a firewall in Linux operating systems, and the specified rule will reject SYN packets, effectively thwarting TCP scans.

Once the firewall in the target network rejects SYN packets, the attacker becomes unable to enumerate open ports within the target network, even if the services are active. When the TCP scan is executed again, it indicates that Port 80 is closed.

By rejecting the SYN packets at the firewall level, the network's security is strengthened, preventing unauthorized access and potential attacks. In this specific scenario, the result of the TCP scan reveals that Port 80 is not accessible or open for communication. This helps safeguard the network and its resources from potential vulnerabilities.
![scan](/assets/img/headers/nmap/4.png)

## Bypass SYN Filter

To bypass the SYN filter when the attacker fails to enumerate open ports using a TCP scan, advanced scanning methods can be employed. One such method is the FIN scan.

### FIN Scan

In a FIN scan, the attacker utilizes a FIN packet to terminate the TCP connection between the source and destination ports. Unlike the SYN packet used in traditional TCP scans, Nmap initiates a FIN scan by sending a FIN packet.

To perform a FIN scan on Port 80 of the target IP address 192.168.0.19, you can use the following command:
```sh
nmap -sF -p 80 192.168.0.19
```
![scan](/assets/img/headers/nmap/5.png)

### NULL Scan (000000)
To further bypass the firewall filter, another advanced scanning method is the NULL scan.

In a NULL scan, a series of TCP packets with a sequence number of "zeros" (0000000) are sent. Since no flags are set in these packets, the destination server does not know how to respond to the request. As a result, the packet is discarded, and no reply is sent back. If no response is received, it indicates that the port is open.

It's important to note that NULL scans are typically effective on Linux machines and may not work on the latest versions of Windows.

To perform a NULL scan on Port 80 of the target IP address 192.168.0.19, you can use the following command:
```sh
nmap -sN -p 80 192.168.0.19
```
![scan](/assets/img/headers/nmap/6.png)

### XMAS Scan

After performing the XMAS scan, we can observe that Port 80 is indeed open. XD

The XMAS scan is a scanning technique that manipulates the PSH, URG, and FIN flags of the TCP header. By setting these flags simultaneously, the packet is illuminated like a Christmas tree. In this scan, the source sends a packet with the FIN, PUSH, and URG flags to a specific port. If the port is open, the destination server will discard the packets and not send any reply back to the source.

To perform an XMAS scan on Port 80 of the target IP address 192.168.0.19, you can use the following command:
```bash
nmap -sX -p 80 192.168.0.19
```
## Block Scan
To block these types of scans, you can utilize iptables rules. Here's how you can block each scan:
- Blocking the FIN Scan:
    - To block the FIN scan, you can use the following iptables rule:
    ```sh
    iptables -I INPUT -p tcp --tcp-flags ALL FIN -j REJECT --reject-with tcp-reset
    ```
    - This rule rejects any incoming TCP packets with the FIN flag set. 

-  Blocking the NULL Scan:
   - To block the NULL scan, you can use the following iptables rule:
   ```sh
   iptables -I INPUT -p tcp --tcp-flags ALL NONE -j REJECT --reject-with tcp-reset
   ```
   - This rule rejects any incoming TCP packets with no flags set.

- Blocking the XMAS Scan:
   - To block the XMAS scan, you can use the following iptables rule:
   ```sh
   iptables -I INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j REJECT --reject-with tcp-reset
   ```
   - This rule rejects any incoming TCP packets with the FIN, PSH, and URG flags set.

![scan](/assets/img/headers/nmap/8.png)
![scan](/assets/img/headers/nmap/9.png)

## Reject Data-length with IPTABLES

To further enhance network security and protect it from FIN, NULL, and XMAS scans, you can apply an additional iptables rule to reject incoming network traffic based on data length. This rule allows you to block TCP connections with a specific data length.

To apply a firewall rule that checks the data length and rejects TCP connections with a length of 60 (as confirmed from the table given above), you can use the following command:
```sh
iptables -I INPUT -p tcp -m length --length 60 -j REJECT --reject-with tcp-reset
```
By implementing this rule, any TCP connections with a data length of 60 will be rejected, thereby preventing potential TCP scans from bypassing the network security measures.

After we scan we can see the port 80 is close.
```bash
nmap -sT -p 80 192.168.0.19
```
![scan](/assets/img/headers/nmap/10.png)

## BYPASS DATA-LENGTH with STEALTH SCAN

To bypass the firewall's data length filter, attackers can utilize a scanning method known as the Stealth Scan.

When the attacker fails to enumerate open ports using a TCP scan, they can employ the Stealth Scan by using the following command:
```sh
nmap -sS -p 80 192.168.0.19
```
In the Stealth Scan, the data length sent by default for TCP connections is 44. This scanning technique closely resembles a TCP scan and is also referred to as a "half-open" scan. It involves sending a SYN packet and receiving a SYN/ACK packet in response from the listening port. However, instead of sending an ACK packet back to the listening port, the Stealth Scan dumps the obtained result without completing the full three-way handshake.

By utilizing the Stealth Scan, attackers can attempt to bypass certain firewall filters that focus on data length, providing them with the opportunity to gather information about open ports and services on the target network.
![scan](/assets/img/headers/nmap/11.png)

## Fragment Scan
The `-f` option in Nmap is used to perform a scan using tiny fragment IP packets. This technique involves splitting the TCP header over multiple packets, making it more challenging for packet filters, intrusion detection systems, and other security mechanisms to detect the scan. For instance, a 20-byte TCP header would be divided into three packets: two packets with eight bytes of the TCP header and one packet with the remaining four bytes.

To perform a scan using tiny fragment IP packets on Port 80 of the target IP address 192.168.0.19, you can use the following command:
```sh
nmap -f -p 80 192.168.0.19
```
However, if the administrator applies firewall filters to reject data lengths of 40, 44, and 60, it will prevent attackers from executing the aforementioned scans, both basic and advanced. The following iptables rules can be applied to achieve this:
```sh
iptables -I INPUT -p tcp -m length --length 60 -j REJECT --reject-with tcp-reset
iptables -I INPUT -p tcp -m length --length 44 -j REJECT --reject-with tcp-reset
iptables -I INPUT -p tcp -m length --length 40 -j REJECT --reject-with tcp-reset
```
By implementing these iptables rules, any TCP connections with data lengths of 60, 44, or 40 will be rejected, effectively blocking the corresponding scans.

Executing the various scans after applying the firewall rules will result in Port 80 being reported as closed:
```sh
nmap -sF -p 80 192.168.0.19 (port 80 is closed)
nmap -sX -p 80 192.168.0.19 (port 80 is closed)
nmap -sN -p 80 192.168.0.19 (port 80 is closed)
nmap -sS -p 80 192.168.0.19 (port 80 is closed)
nmap -sT -p 80 192.168.0.19 (port 80 is closed)
```
## DATA LENGTH SCAN
When attackers is unable to enumerate open port by applying above scan then he should go with nmap "data-lenght" which will bypass above firewall filtre too:
```sh
nmap --data-length 12 -p 80 192.168.0.19 this is working
```
![scan](/assets/img/headers/nmap/15.png)

But how can we stop this attack? So, we use REJECT LENGTH SIZE 1 to 100. If the administrator knows about the nmap data-length scan, he or she should block all data lengths to stop attackers from scanning the network by running the following Iptable rules:
```sh
iptables -I INPUT -p tcp -m length --length 1:100 -j REJECT --reject-with tcp-reset
```

Now we can try again the scan
```sh
nmap --data-length 32 -p 80 192.168.0.19 --> faild
nmap --data-length 12 -p 80 192.168.0.19 --> faild
nmap --data-length 113 -p 80 192.168.0.19 --> succed
```

This is the final story, security is just a concept. All stuff can be break.