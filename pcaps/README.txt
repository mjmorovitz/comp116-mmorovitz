set1.pcap
1. There are 861 packets
2. FTP was used
3. FTP is not secure as it sends information such as usernames and passwords in plain text to the server.
4. A secure alternative to FTP  is SCP. SFPT is another more secure option the FTP.
5. The server IP is 192.168.1.8
6. username: defcon password mlngisablowhard
7. There are 6 files transfered.
8.     
-rw-------    1 1001     1003        58341 Sep 14 18:22 CDkv69qUsAAq8zN.jpg 
-rw-------    1 1001     1003        57529 Sep 14 18:22 CJoWmoOUkAAAYpx.jpg 
-rw-------    1 1001     1003        34876 Sep 14 18:22 CKBXgmOWcAAtc4u.jpg
-rw-------    1 1001     1003        56756 Sep 14 18:22 CLu-m0MWoAAgjkr.jpg
-rw-------    1 1001     1003        72343 Sep 14 18:22 CNsAEaYUYAARuaj.jpg
-rw-------    1 1001     1003       108576 Sep 14 18:22 COaqQWnU8AAwX3K.jpg

   

   
set2.pcap
10. There are 77982 packets in this set.
11. larry@radsot.com" "Z3lenzmej"
12. I used the Ctrl F feature (or frame contains [SEARCH WORD]) and searched for strings containing "login", "passwd", "pass", "password", and "user". The I searched the TCP streams to find releavant information. I also looked through the data displayed when you open a pcap file in ettercap
13. protocol = IMAP, Source IP = 10.125.15.197 Destination IP = 87.120.13.118 Source port = 44344 Destination Port = 143, Domain = mail.radspot.com
14. The username and password appear to be valid as the server response was _infraware-p-email__7 OK LOGIN Ok.

set3
15. I found 3 username-password pair in this packet set. 
user seymore
passwd butts

user nab01620@nifty.com
password takirin1

USER: jeff 
PASS: asdasdasd  

16. for user seymore:
Protocol = HTTP, Source IP = 10.134.15.231 Destination IP = 162.222.171.208, Domain = forum.defcon.org Source Port = 51668, Destination Port = 80

for user nab01620:
Potocol IMAP, Source Ip = 10.115.15.213 Desitination IP = 210.131.4.155, Domain : no response from name resolve Source Port = 54475, Destination 143

for user jeff
Protocol HTTP, Source Ip 54.191.109.23, Domain ec2.intelctf.com/C, Port 80
17. The username and password for seymore was not valid as access was not granted (403 error). The same applies to username jeff (401).
18. See screenshots in repo. These came from ettercap.
General Questions:
19. I verified the successful usernames and passwords but following the TCP stream and looking for phrases such as "200 Status", "ok", or "login successful"
20. The advise I would use would be to use a secure file transfer protocol such as ftps instead of ftp and https instead of http. Additionally, always use SSL/TLS when accessing emails with IMAP to secure data such as usernames and passwords. 



