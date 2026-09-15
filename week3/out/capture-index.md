# Capture index — `out/dns.pcapng`

Every row is one real DNS packet this machine sent or received. Frame numbers match the pcapng.

> SYNTHESIZED FRAMING — the DNS payload of every packet in this file is the exact byte string this machine sent to, or received from, the named server over UDP port 53, with the real transaction IDs, the real ephemeral source ports and the real timestamps. Wireshark, tshark and Npcap could not be installed on this machine, so there was no capture driver to record the frames. The Ethernet, IPv4 and UDP headers were therefore reconstructed by task2_steering.py: the MAC addresses are locally-administered placeholders (02:00:00:00:00:01/02) rather than this host's real MAC, and the IPv4 TTL is set to 64 in both directions and is NOT an observed value. Everything above the UDP header is genuine traffic; everything below it is reconstruction. See out/report.md section 7.

| frame | dir | peer | kind | qname | txid | an | ns | ar | DNS bytes |
|---:|---|---|---|---|---|---:|---:|---:|---:|
| 1 | tx | `198.41.0.4` | query | `www.adobe.com` | `0x7453` | 0 | 0 | 1 | 42 |
| 2 | rx | `198.41.0.4` | delegation | `www.adobe.com` | `0x7453` | 0 | 13 | 27 | 838 |
| 3 | tx | `192.5.6.30` | query | `www.adobe.com` | `0x1e84` | 0 | 0 | 1 | 42 |
| 4 | rx | `192.5.6.30` | delegation | `www.adobe.com` | `0x1e84` | 0 | 6 | 1 | 175 |
| 5 | tx | `198.41.0.4` | query | `a1-217.akam.net` | `0xbfa8` | 0 | 0 | 1 | 44 |
| 6 | rx | `198.41.0.4` | delegation | `a1-217.akam.net` | `0xbfa8` | 0 | 13 | 27 | 837 |
| 7 | tx | `192.5.6.30` | query | `a1-217.akam.net` | `0x17c4` | 0 | 0 | 1 | 44 |
| 8 | rx | `192.5.6.30` | delegation | `a1-217.akam.net` | `0x17c4` | 0 | 8 | 17 | 561 |
| 9 | tx | `193.108.91.67` | query | `a1-217.akam.net` | `0xbbd0` | 0 | 0 | 1 | 44 |
| 10 | rx | `193.108.91.67` | answer | `a1-217.akam.net` | `0xbbd0` | 1 | 0 | 1 | 60 |
| 11 | tx | `193.108.91.217` | query | `www.adobe.com` | `0xa3bc` | 0 | 0 | 1 | 42 |
| 12 | rx | `193.108.91.217` | answer | `www.adobe.com` | `0xa3bc` | 1 | 0 | 1 | 83 |
| 13 | tx | `198.41.0.4` | query | `www.adobe.com.edgesuite.net` | `0x5fcc` | 0 | 0 | 1 | 56 |
| 14 | rx | `198.41.0.4` | delegation | `www.adobe.com.edgesuite.net` | `0x5fcc` | 0 | 13 | 27 | 849 |
| 15 | tx | `192.5.6.30` | query | `www.adobe.com.edgesuite.net` | `0x8502` | 0 | 0 | 1 | 56 |
| 16 | rx | `192.5.6.30` | delegation | `www.adobe.com.edgesuite.net` | `0x8502` | 0 | 8 | 17 | 577 |
| 17 | tx | `193.108.91.2` | query | `www.adobe.com.edgesuite.net` | `0x80d6` | 0 | 0 | 1 | 56 |
| 18 | rx | `193.108.91.2` | answer | `www.adobe.com.edgesuite.net` | `0x80d6` | 1 | 0 | 1 | 88 |
| 19 | tx | `198.41.0.4` | query | `a1319.dscr.akamai.net` | `0xb269` | 0 | 0 | 1 | 50 |
| 20 | rx | `198.41.0.4` | delegation | `a1319.dscr.akamai.net` | `0xb269` | 0 | 13 | 27 | 843 |
| 21 | tx | `192.5.6.30` | query | `a1319.dscr.akamai.net` | `0xb9fa` | 0 | 0 | 1 | 50 |
| 22 | rx | `192.5.6.30` | delegation | `a1319.dscr.akamai.net` | `0xb9fa` | 0 | 8 | 11 | 394 |
| 23 | tx | `193.108.88.1` | query | `a1319.dscr.akamai.net` | `0x6502` | 0 | 0 | 1 | 50 |
| 24 | rx | `193.108.88.1` | delegation | `a1319.dscr.akamai.net` | `0x6502` | 0 | 8 | 10 | 374 |
| 25 | tx | `88.221.81.192` | query | `a1319.dscr.akamai.net` | `0xe902` | 0 | 0 | 1 | 50 |
| 26 | rx | `88.221.81.192` | answer | `a1319.dscr.akamai.net` | `0xe902` | 9 | 0 | 1 | 194 |
| 27 | tx | `198.41.0.4` | query | `www.stanford.edu` | `0x85c6` | 0 | 0 | 1 | 45 |
| 28 | rx | `198.41.0.4` | delegation | `www.stanford.edu` | `0x85c6` | 0 | 13 | 27 | 840 |
| 29 | tx | `192.5.6.30` | query | `www.stanford.edu` | `0xb712` | 0 | 0 | 1 | 45 |
| 30 | rx | `192.5.6.30` | delegation | `www.stanford.edu` | `0xb712` | 0 | 6 | 7 | 312 |
| 31 | tx | `171.64.7.115` | query | `www.stanford.edu` | `0x2029` | 0 | 0 | 1 | 45 |
| 32 | rx | `171.64.7.115` | answer | `www.stanford.edu` | `0x2029` | 1 | 0 | 1 | 88 |
| 33 | tx | `198.41.0.4` | query | `stanford.netlifyglobalcdn.com` | `0x445f` | 0 | 0 | 1 | 58 |
| 34 | rx | `198.41.0.4` | delegation | `stanford.netlifyglobalcdn.com` | `0x445f` | 0 | 13 | 27 | 854 |
| 35 | tx | `192.5.6.30` | query | `stanford.netlifyglobalcdn.com` | `0xe3ce` | 0 | 0 | 1 | 58 |
| 36 | rx | `192.5.6.30` | delegation | `stanford.netlifyglobalcdn.com` | `0xe3ce` | 0 | 8 | 9 | 410 |
| 37 | tx | `45.54.30.1` | query | `stanford.netlifyglobalcdn.com` | `0x2192` | 0 | 0 | 1 | 58 |
| 38 | rx | `45.54.30.1` | answer | `stanford.netlifyglobalcdn.com` | `0x2192` | 2 | 0 | 1 | 90 |
