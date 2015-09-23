Comp116 Security
Assignment #2
Author: Walton Lee

1. There are 861 Packets
2. File transfer occurs using FTP (File Transfer Protocol)
3. FTP is insecure because it transmit data in plain text without encryption
4. SFTP is the secure alternative
5. 192.168.1.8
6. USER:defcon
   PASS:mlngisablowhard
7. 6 files were transfered
8. CDkv69qUsAAq8zN.jpg
   CJoWmoOUkAAAYpx.jpg
   CKBXgmOWcAAtc4u.jpg
   CLu-m0MWoAAgjkr.jpg
   CNsAEaYUYAARuaj.jpg
   COaqQWnU8AAwX3K.jpg
10. There are 77982 Packets
11. 1, ("larry@radsot.com", "Z3lenzmej")
12. I found the pair by sorting the info category in wireshark
    and then screening through all the request packets for usernames
    and passwords.
13. IMAP, 87.120.13.118, Port#: 143, amazon.com? mta985.news.logitravel.com
14. The one USER/PASS pair successfully logged in.
15 & 16. 2 pairs
    USER: seymore PASS: butts, domain:forum.defcon.org, IP:162.222.171.208
    PORT: 80, Protocol: HTTP

    USER:nab01620@nifty.com, PASS: Nifty->takirnl, Protocol: IMAP
    IP: 210.131.4.155.145, Port: 143, domain: nifty.com?
17: only nifty is legitimate
18:
74.122.189.133	api.squareup.com
74.122.190.78	api.squareup.com
74.125.129.108	pd-in-f108.1e100.net
74.125.28.121	ghs.l.google.com
74.125.28.141	appspot.l.google.com
74.125.28.157	pc-in-f157.1e100.net
74.125.28.188	pc-in-f188.1e100.net
74.125.28.189	0.client-channel.google.com
74.125.28.189,10.134.15.231	0.client-channel.google.com,10.134.15.231
74.125.28.189,10.134.15.231	1.client-channel.google.com,10.134.15.231
74.125.28.189	1.client-channel.google.com
74.125.28.189	pc-in-f189.1e100.net
74.125.28.95	pc-in-f95.1e100.net
75.102.27.238	75-102-27-238-host.colocrossing.com
80.47.27.115	host-80-47-27-115.as13285.net
82.69.121.229	82-69-121-229.dsl.in-addr.zen.co.uk
84.46.43.124	port-11089.pppoe.wtnet.de
85.229.1.92	85.229.1.92
85.229.1.92	c-5c01e555.03-268-6c6b701.cust.bredbandsbolaget.se
88.192.67.232	dsl-hkibrasgw5-58c043-232.dhcp.inet.fi
91.189.95.36	manpages.ubuntu.com
91.190.218.69	conn.skype.akadns.net
93.184.216.180	cs346.wac.edgecastcdn.net
94.249.182.130	clegg.wreent.net
96.17.10.59	a96-17-10-59.deploy.akamaitechnologies.com
98.138.47.63	a.it.vip.ne1.yahoo.com

I first set wireshark's preferences such that it would resolve host names
of IP addresses.
I then used tshark with the flags: 
tshark -r set3.pcap -T fields -e ip.dst -e ip.dst_host | sort | uniq

19: I followed the TCP stream of the request packets with the username and
    password, then I checked to the stram for some sort of logon confirmation
20: either use a VPN or utilize protocols that encrypt your packets

 

