 MDK3 Documentation

![k2wrlz logo](docs/k2wrlz.png)  
  
MDK3 Documentation  
  

MDK is a proof-of-concept tool to exploit common IEEE 802.11 protocol weaknesses.  
It is your responsibility to make sure you have permission from the network owner before running MDK against it.  

  
  
MDK3 is a Wi-Fi testing tool from ASPj of k2wrlz, it uses the osdep library from the aircrack-ng project to inject frames on several operating systems.  
Many parts of it have been contributed by the great aircrack-ng community:  
Antragon, moongray, Ace, Zero\_Chaos, Hirte, thefkboss, ducttape, telek0miker, Le\_Vert, sorbo, Andy Green, bahathir, Dawid Gajownik and Ruslan Nabioullin.  
THANK YOU!  
  
MDK3 is licenced under the [GPLv2](http://www.gnu.org/licenses/gpl-2.0.html) or later.  
  
  
Contents:  
1\. Setting up your environment  
2\. Getting MDK3 to run (Compiling MDK3)  
3\. How to use MDK3  
4\. The different test modes  
  
  
  
1\. Setting up your environment  
  
MDK3 is a tool that "injects" data into wireless networks. "Injection" is the possibility to send self-made data through the air without being connected or associated to any network or station. MDK3 is used to send valid and invalid packets, which belong to the wireless management and not to regular data connections. This is only possible with this Injection technique. Sadly, this is something, WiFi equipment has NOT been built for in the first place! To enable the injection feature on your wireless card, you possibly need modified drivers. A lot of work has already been done by several hackers (including me) to make these modified drivers available for a lot of hardware. Furthermore, the new wireless subsystem [mac80211](http://linuxwireless.org/) in the Linux kernel supports Injection out of the box for many drivers and cards.  
To set up your driver for Injection, please visit [www.aircrack-ng.org](http://www.aircrack-ng.org) and follow the [Driver Documentation](http://www.aircrack-ng.org/doku.php?id=compatibility_drivers) there.  
MDK3 uses the drivers and Injection routines from this project and its predecessor. Thus, all drivers listed there should work with MDK3. (Some special hardware, like Intel Centrino (ipw2200) is NOT supported since they can only inject data, and no management information!)  
MDK3 works on Linux and maybe FreeBSD currently, it may also run on Windows, but you need very special and expensive drivers and hardware there, so it is totally unsupported by MDK3 and aircrack-ng. MDK3 runs best with a pretty up-to-date kernel and drivers. Use the recommended drivers and patches ([compat-wireless](http://www.aircrack-ng.org/doku.php?id=compat-wireless)) mentioned in the aircrack-ng Wiki.  
  
  
2\. Getting MDK3 to run (Compiling MDK3)  
  
Some Linux distributions already contain a precompiled mdk3 binary. Sometimes they are pretty old and buggy. You are advised to always use the most up-to-date version, since version changes usually have many new features and bugfixes.  
To compile mdk3, go to the directory, where you extracted the tarballs contents and simply type make  
To copy the compiled binary to your /usr/local/sbin directory (installing it), type make install afterwards.  
mdk3 needs libpthread and libpcap. pcap is possibly not installed on your machine, use your package manager to install the development package for pcap (ie. zypper in libpcap-devel for SuSE or apt-get install libpcap-dev for Debian/Ubuntu)  
  
  
3\. How to use MDK3  
  
Using MDK3 is quite simple, since it comes with lots of help screens directly included.  
You can easily access them by typing only mdk3  
MDK3 displays the main help screen. To see all possible options, type mdk3 --fullhelp  
To see only information for a specific test, type mdk3 --help followed by the test mode identifier (b, a, p, d, m, x, w, f or g)  
  
Before you can use MDK3, you need to setup your wireless adaptor. As far as there are different driver architectures, the way to setup your adaptor may vary depending on which driver is in use. To make this procedure easy, it is recommended to use airmon-ng from the aircrack project, since it can setup almost every known driver correctly.  
Read the [documentation for airmon-ng](http://www.aircrack-ng.org/doku.php?id=airmon-ng) to learn how to set your WiFi card into the proper mode.  
  
IMPORTANT: You need to set your device to the channel where the target AP/client is, otherwise it won't work! This is a very common error.  
  
To find APs and clients, it is recommended to use airodump-ng. Simply start it with airodump-ng \[your_interface\] first, to see the available stations. If you have decided on one CHANNEL where to run the tests on, you should restart airodump and set it to STAY on this specific channel, so your card won't change channels anymore to find other stations. You can do this with airodump-ng -c \[channel\] \[your_interface\]  
The good thing of using airodump-ng is, that you don't need to care about setting your card up correctly since airmon-ng and airodump-ng already did this job.  
  
Your hardware is now correctly set up, and you can start using MDK3.  
  
Another important notice for professional users: Some drivers do not correctly echo back injected frames to the system, thus your injected packets won't be seen if you sniff on the interface on which you are injecting. To check if the frames are sent correctly you need to setup another inteface on the same channel and sniff the injected frames with it! You can also use aireplay-ng's injection test to see if everything is alright.  
  
  
4\. The different test modes  
  
b   - Beacon Flooding  
  
AccessPoints send out approximately 10 beacon frames per second. They are to identify the network. When you scan for networks, your card does in fact look for beacon frames on every available channel. With MDK3, it is possible to send those beacon frames, too. Therefor you are able to create as many networks as you like, always keep in mind, that those networks are fake, and nobody can actually connect to them. People will see those networks when they scan with their WiFi device. Windows does scan automatically as long as it isn't connected and shows an info, if a network is found. Additionally, this mode can be used to hide a network by generating thousands of fake networks with the same name as the original one. This mode has several options to set network name, i encryption, speed etc. So read on to get familiar with them:  
  
      -n <ssid>  
         Use SSID <ssid> instead of randomly generated ones  
         This lets you set the name of the network. Only networks with the given name will be faked. This is used if you want to hide a network.  
      -f <filename>  
         Read SSIDs from file  
         This lets you read the names for the networks from a file. This way you can fake multiple networks at once.  
      -v <filename>  
         Read MACs and SSIDs from file. See example file!  
         This is used to fake only a very specific set of networks. Every line in this file consists of the APs adress and its name. See the example file fakeap-example.txt on how to use it.  
      -t <adhoc>  
         -t 1 = Create only Ad-Hoc network  
         -t 0 = Create only Managed (AP) networks  
         without this option, both types are generated  
         Select to fake a real network, or an Ad-Hoc network with clients only. (networks without APs, where peers communicate directly) or both.  
      -w <encryptions>  
         Select which type of encryption the fake networks shall have  
         Valid options: n = No Encryption, w = WEP, t = TKIP (WPA), a = AES (WPA2)  
         You can select multiple types, i.e. "-w wta" will only create WEP and WPA networks  
      -b <bitrate>  
         Select if 11 Mbit (b) or 54 MBit (g) networks are created  
         Without this option, both types will be used.  
      -m  
         Use valid accesspoint MAC from built-in OUI database  
         Usually, MDK3 generates networks with a random adress. But as far as not all adresses are used by actual hardware, it would be easy to detect most of mdk3's network as Fakes.  
         This option refers to the adress database included in MDK3 to generate only AcessPoints with adresses from known hardware vendors. With this option it is hard to say, if a network is fake or not.  
      -h  
         Hop to channel where network is spoofed  
         This is more effective with some devices/drivers  
         But it reduces packet rate due to channel hopping.  
         This makes MDK3 to change your card's channel to the channel where the fake network should actually be. Good thing about this is, its harder to determine if this network is fake, since the channel given in the beacon data matches the channel the packet is send on. Bad thing is, your card needs some time to change to a specific channel. So this slows down the injection speed. You could avoid this by generating fake networks on one channel only (see -c option below), but in this case, the targets don't need to change their channels in order to find the correct AP, thus they may find the real AP faster.  
      -c <chan>  
         Create fake networks on channel <chan>. If you want your card to  
         hop on this channel, you have to set -h option, too.  
      -s <pps>  
         Set speed in packets per second (Default: 50)  
         More speed = More fake networks.  
  
  
EXAMPLES:  
  
There is your WPA2 AES network named "Hack me" on channel 11, supporting up to 54 MBit with lots of clients. You want to confuse attackers by generating some fake clone networks:  
  
mdk3 \[your_interface\] b -n "Hack me" -b 54 -w a -m -c 11  
  
The b activates beacon flood mode, -n sets the name, -b 54 makes it 54 MBit, -w a enables WPA2/AES only, -m makes MDK3 only use valid adresses so the attacker will have a hard time to filter and -c sets the correct channel.  
Do not forget to set your card's channel before your start such it! You could also use -h option for this.  
  
  
a   - Authentication Denial-Of-Service  
  
When a station connects to an AccessPoint, it needs to fulfill several steps of Authentication. The two basic steps are Authentication and Association. The first step starts the whole process and asks the AP if another station may connect to it, and lets the AP decide if the new client is allowed. A MAC Filter would deny this request if an unknown station would try to connect. In the second step, the encryption is checked. Most APs use the Open mode, so the Association Phase is always accepted, and the real check if a clients key is valid is done later (i.e. in the EAP phase for WPA). The weak point of this is, that you can start multiple requests and forget about them, but the AP needs to keep those request in its memory in order to complete it. This Denial-of-Service-Mode starts as much requests as possible and keeps track of the answers, the AP sends. You can execute this test on multiple APs at once, or you can select the intelligent variant, where mdk3 does itself keep track about clients, and even re-injects valid Data packets it intercepts from the network, so an AP may not be able to distinguish real and fake clients, and may start dropping legitimate ones to free up space.  
  
      -a <ap_mac>  
         Only test the specified AP. Otherwise mdk3 will test all APs found on the current channel (you could use some other tool to hop channels to attack all APs in range.)  
      -m  
         Use valid client MAC from built-in OUI database, so the AP can't filter invalid adresses.  
      -i <ap_mac>  
         Perform intelligent test on AP.  
         This test connects clients to the AP and reinjects sniffed data to keep them alive.  
      -s <pps>  
         Set speed in packets per second (Default: unlimited)  
  
  
EXAMPLES:  
  
You want to test if your own network is vulnerable to Denial-of-Service attacks. So first, you try a simple attack to see how your AP handles too many connected clients. Usually at a certain limit (128 or 256 clients), the AP denies additional clients. Cheap APs also tend to FREEZE and need to be resetted, so be careful with this! Let's assume your AP has 00:00:11:22:33:44 as hardware adress, this is the first test:  
  
mdk3 \[your_interface\] a -a 00:00:11:22:33:44 -ma activates the Auth DoS mode. -a selects your target AP, -m makes mdk3 use only valid adresses to make filtering difficult. After a few seconds mdk3 may show one or mor of those messages:  

*   AP 00:00:11:22:33:44 is responding: Your AP is responding to mdk3's fake clients. This just lets you know, that your test is working.
*   AP 00:00:11:22:33:44 has stopped responding and seems to be frozen after 157 clients: Your AP stopped responding to mdk3's requests. Check if your AP is still functional. If not, it is vulnerable to Auth DoS attacks, and needs to be reset if one occurs! You should request a fix from your vendor!
*   AP 00:00:11:22:33:44 is reporting ERRORs and denies connections after 251 clients: Your AP stopped accepting new clients, but did not crash, and correctly denies new ones. Your network is now FULL, but stiull functional. However you cannot connect to this AP anymore until the fake clients from mdk3 time out and the AP accept new ones again. There is nothing wrong with that, this DoS condition is compliant with the IEEE 802.11 standard!  
    

Afterwards, you may want to try the intelligent test, that makes it hard for your AP to distinguish fake and real clients. This causes a constant Denial of Service for new clients, as long as the attack is running. And as soon as a legitimate clients disconnects, he cannot re-join the network.  
  
mdk3 \[your_interface\] a -i 00:00:11:22:33:44  
  
mdk3 will print statistics each second:  
Clients: Created:   67   Authenticated:    0   Associated:    0   Denied: 5461   Got Kicked:    0  
Data   : Captured:    0   Sent:    0   Responses:    0   Relayed:    0  

*   Created: Number of fake clients mdk3 currently handles and tries to connect and keep connected to the network
*   Authenticated: Number of successful Authentication cycles
*   Associated: Number of successful Association cycles
*   Denied: Number of failed cycles (because AP is full)
*   Got kicked: Number of fake clients that once were connected but the AP sent Deauthentication packets to
*   Captured: Number of VALID Data packets that have been captured
*   Sent: Number of Data packets that have been sent to the network with a fake clients identity
*   Responses: Number of responses the fake clients got after sending data
*   Relayed: Number of Data packets the AP accepted from the fake clients (AP forwards incoming packets so we know when it accepted one, if we intercept the forwarded one!)  
    

In this example, the intelligent attack has been started about 10 minutes after the standard one. As you can see, the AP is STILL denying any new client! So be careful when you test a network that cannot afford some downtime!  
  
  
  
p   - Probing  
  
The IEEE standard defines Probe packets. Those packets allow a station to send a request for a certain network into the air, with all matching APs responding to it. With those packets you can check, if an AP is in your range (ie. if you can reach it and it reaches you). Most APs have a feature called "hidden SSID". With a hidden SSID, a network cannot be "found" with Windows, and will be displayed on other Systems as "Hidden". The beacon frames emitted by those APs do NOT contain the networks name. Instead they either contain ZEROS for each character in the SSID, or only a single Zero. In order to connect to such a hidden network, an attacker must find out the networks real name. As far as the network's name is being transmitted in plaintext upon Association to the AP, an attacker could simply wait until some client connects to the AP or disconnect an already connected one with aireplay-ng or any other Deauthentication tool (mdk3 can do it too, Mode d), and wait for it to reconnect (which it usually does instantly). However, if there is NO CLIENT connected, the SSID stays hidden. With mdk3 however, you are able to try SSIDs from a Wordlist or via Bruteforce. It sends Probe Frames and waits for responses. If you hit the right SSID, the AP will respond to you, and it's name isn't hidden anymore. If you are lucky, the AP keeps the original length of the real SSID in its beacon frames. mdk3 will detect that and will only try SSIDs that match.  
  
      -e <ssid>  
         SSID to probe for - If you know the target SSID already and/or just want to check if an AP is in your range.  
      -f <filename>  
         Read SSIDs from file for bruteforcing hidden SSIDs  
      -t <bssid>  
         Set MAC address of target AP  
         With a target set, mdk3 will only print responses from this network, and stops when the Wordlist ends.  
      -s <pps>  
         Set speed (Default: 400)  
      -b <character sets>  
         Use full Bruteforce mode (recommended for short SSIDs only!)  
         You can select multiple character sets at once:  
         \* n (Numbers:   0-9)  
         \* u (Uppercase: A-Z)  
         \* l (Lowercase: a-z)  
         \* s (Symbols: ASCII)  
      -p <word>  
         Continue bruteforcing, starting at <word>.  
  
  
EXAMPLES:  
  
Let's assume you got a pretty important network, that is well secured. Lets say this network is only used a few hours each month, so an attacker may not be lucky to catch a client authenticating to it. You decide to add some extra security to that network by disabling the SSID broadcasting. That way an attacker may not be able to connect to it, since he doesn't know its SSID, and thus may not be able to run Authentication Denial-of-Service attacks. You select a pretty short SSID, but you add a special character to it, hoping that it cannot be guessed: aa1*  
Let's test if this SSID can be decloaked by a Wordlist attack:  
  
mdk3 \[your_interface\] p -f useful_files/common-ssids.txt -t 00:00:11:22:33:44Waiting for a beacon frame from target to get its SSID length.  
SSID length is 4  
Trying SSID: 3Com                                            
Trying SSID: AZRF                                            
Trying SSID: WiFi                                            
Trying SSID: mine                                            
Packets sent:     44 - Speed:   20 packets/sec  
Wordlist completed.  
  
Sadly, your AP does only overwrite the SSID itself with ZEROS, not its length tag, so mdk3 knows, your SSID is only 4 characters long. Therefor, it tries only those words in the specified file, that a 4 characters long. Luckily, aa1* is not being found in the list, and mdk3 cannot find the hidden SSID. The attacker may now try to use Bruteforcing, since the SSID is very short. Let's say he already tried several character sets, and wants to finally try all possible characters:  
  
mdk3 \[your_interface\] p -t 00:00:11:22:33:44 -b lnusWaiting for a beacon frame from target to get its SSID length.  
SSID length is 4  
Trying SSID: aaaa                                            
Trying SSID: aac&                                            
Trying SSID: aag-                                            
Trying SSID: aak<                                            
Trying SSID: aao@                                            
Trying SSID: aas^                                            
Trying SSID: aaw{                                            
Trying SSID: aa0{                                            
Probe Response from target AP with SSID aa1*                 
Job's done, have a nice day :)  
  
This time, mdk3 is successful.-b lnus means, start with lowercase, then numbers, then Uppercase and finally symbols. After about 2500 tries, the SSID has been found, and therefor does not add much extra security to your network. Consider using a longer one!  
  
  
  
d   - Deauthentication ans Disassociation  
  
If a station wants to leave a network, it sends a Deauthentication packet to the AP to deregister itself from it. Additionally, the AP is allowed to disconnect stations when it thinks it is necessary (for example, the AP is full, and the oldest stations gets kicked from it to allow new clients to connect). As far as those packets are not encrypted our signed (if you are not using the new amendment [IEEE_802.11w](http://en.wikipedia.org/wiki/IEEE_802.11w-2009)), an attacker can easily forge them to disconnect legitimate clients from your AP. mdk3 is capable of creating different types of those packets, with different options:  

*   Deauthentication from AP to client: mdk3 injects a deauthentication packet with the MAC Adress of the AP to the Station, telling the station is has been disconnected for unspecified reasons.
*   Deauthentication from client to AP: mdk3 injects a deauthentication packet from the Station to the AP, telling the AP, the station is leaving the network.
*   Disassociation from AP to client: mdk3 tells the client, it has been kicked because the AP is full.  
    
*   Disassociation from client to AP: mdk3 tells the AP, the client is leaving the network.

mdk3 listens on the current channel for Data packets, extracts the adresses of AP and Station from them, and sends one packet of each type. Every second, a status message is displayed, if something has happened.  
  
      -w <filename>  
         Read file containing MACs not to care about (Whitelist mode)  
         Put the MAC adresses of stations and APs, who shall NOT be attacked in this file, mdk3 will skip them  
      -b <filename>  
         Read file containing MACs to run test on (Blacklist Mode)  
         Put MAC adresses of stations and APs in this file, who SHALL BE attacked.  
      -s <pps>  
         Set speed in packets per second (Default: unlimited)  
      -c \[chan,chan,chan,...\]  
         Enable channel hopping. Without providing any channels, mdk3 will hop an all  
         14 b/g channels. Channel will be changed every 3 seconds.  
  
EXAMPLE:  
  
mdk3 \[your_interface\] d -c 1,6,11Disconnecting 00:04:0E:91:5C:56 from 00:1D:E5:7A:18:B9 on channel 1  
Disconnecting 00:04:0E:91:5C:56 from 00:1D:E5:7A:18:B9 on channel 1  
Disconnecting 00:04:0E:91:5C:56 from 00:1D:E5:7A:18:B9 on channel 1  
Disconnecting 00:04:0E:91:5A:77 from 00:1D:E5:7A:15:CE on channel 6  
Disconnecting 00:04:0E:91:5A:77 from 00:1D:E5:7A:15:CE on channel 6  
Disconnecting 00:23:08:DD:4A:FE from 00:1D:E5:7A:43:00 on channel 11  
Disconnecting 00:04:0E:91:5C:56 from 00:1D:E5:7A:18:B9 on channel 1  
Packets sent:    117 - Speed:   16 packets/sec  
  
mdk3 hops on channel 1, 6 and 11, and disconnects every station found there. Most stations try to reconnect, however, almost no communication is possible anymore, because they mostly get disconnected again, as soon as they re-request their IP-Adresses with DHCP and ARP, which triggers another Deauthentication cycle in mdk3. Use 802.11w if available or some IDS to at least detect such attacks on your network.  
  
  
m   - Michael shutdown exploitation (TKIP)  
      Cancels all traffic continuously  
  
EXAMPLES:  
  
x   - 802.1X tests  
  
EXAMPLES:  
  
  
And for those who read this document until the end, here is the special Multi Destruction Mode to really shutdown and destroy a network.  
WARNING: This could REALLY shutdown every communication, even until the hardware is manually resetted. This can crash drivers, computers and APs alike! So consider yourself warned! Run these commands only, if there is no important data transmitted and you can afford some downtime!  
  
  
  
(c) Pedro Larbig 2007
