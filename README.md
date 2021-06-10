# DNS-Packet-Injection


The program can be run using the command "go run dnspoision.go -i interface -f hostnames [expression]"

Also running the command "go run dnspoison.go -help" gives the information regarding usage of the command

  -f string
        Read a list of IP address and hostname pairs 
  -i string
        Interface to listen and inject packets


=> Here -f flag is used to indicate the path to file containing the hostnames and -i flag is used to indicate the interface to listen the packets on. 

=> The program also accepts the BPF expression which can be specified without any flags

=> If no hostname file path is specified all requests will be spoofed.

=> If -i flag is not set, a default interface "eth0" is picked to listen if available else, the first available interface is chosen.

=> If the -i flag is passed with wrong values a default interface is picked as above.


# Logic for poisioning program:

=> First, the traffic is segregated to only handle questions and no responses and if the question name passed by victim matches the hostname/baseurl present in the hostnames file, a response is sent back using the ip mapped to the same hostname in the file.

=> Else, the attacker's ip is chosen to send a response to all incoming queries.


Example programs: 

1. Poisoning using hostsfile

go run dnspoison.go -i eth0 -f /home/amogh/poisonhosts

Here poisonhosts is the file name containing the following details:
172.25.90.238 www.bankofamerica.com
172.25.90.238 www.tcpdump.org
172.25.90.238 www.cs.stonybrook.edu

The tracefile for this is "spoofed.pcap"

2. go run dnspoison.go

Here, eth0 is the interface chosen by defaultand all requests will be spoofed as indicated in the pcap file "allSpoofed.pcap"


# DNS Spoof Detection:

The program can be run using the command "go run dnsdetect.go -i interface -r tracefile [expression]"

Also running the command "go run dnsdetect.go -help" gives the information regarding usage of the command
  
  -i string
        Interface to listen and inject packets
  -r string
        Read packets from given tracefile


=> Here -r flag is used to indicate the path to tracefile

=> The program also accepts the BPF expression which can be specified without any flags

=> If both -i and -r flags are passed values, the detection is done from the tracefile passed

=> If -i flag is not set, a default interface "eth0" is picked to listen if available else, the first available interface is chosen.

=> If -i flag is passed with wrong values then a default interface is picked as described above.


Logic for dns poisoning detection:
=> For dns poisoning detection, I have written code to check for the steps I had initially used in my attack i.e., checking if the IPs are a subset of the original other packet and also verifying the TTLs.

=> This works for the case of false positives too because IPs could be a susbet of other packet and I feel it is highly unlikely for the attacker to have guessed the TTL exactly.

Sample output : 


1. Detection of spoofing in a given pcap file when poisoning was done using poisoinhosts file

go run dnsdetect.go -i eth0 -r /home/amogh/Desktop/spoofed.pcap

2021-04-09 13:09:45.184064 -0400 EDT DNS poisoning attempt
TXID 0x3b1b Request www.bankofamerica.com
Answer1 wwwui.ecglb.bac.com 171.161.116.100 Answer2 172.25.90.238 
2021-04-09 13:09:51.603708 -0400 EDT DNS poisoning attempt
TXID 0xda66 Request www.tcpdump.org
Answer1 192.139.46.66 159.89.89.188 Answer2 172.25.90.238 
2021-04-09 13:09:58.379557 -0400 EDT DNS poisoning attempt
TXID 0x6dfd Request www.cs.stonybrook.edu
Answer1 live-compscisbu.pantheonsite.io fe2.edge.pantheon.io 23.185.0.2 Answer2 172.25.90.238

2. Detection of spoofing in a given pcap file when all poisoing was done for all rquests i.e, without hosts file.

go run dnsdetec.go -r /home/amogh/Desktop/allSpoofed.pcap

2021-04-09 16:12:53.529634 -0400 EDT DNS poisoning attempt
TXID 0x5716 Request SEP1.campus.stonybrook.edu
Answer1 172.25.90.238 Answer2 129.49.23.177 
2021-04-09 16:12:59.980847 -0400 EDT DNS poisoning attempt
TXID 0x4288 Request www.google.com
Answer1 172.253.63.147 172.253.63.106 172.253.63.105 172.253.63.104 172.253.63.99 172.253.63.103 Answer2 172.25.90.238 
2021-04-09 16:13:07.069546 -0400 EDT DNS poisoning attempt
TXID 0x72ca Request www.bankofamerica.com
Answer1 wwwui.ecglb.bac.com 171.161.100.100 Answer2 172.25.90.238 
2021-04-09 16:13:14.585984 -0400 EDT DNS poisoning attempt
TXID 0xdbd5 Request SEP1.campus.stonybrook.edu
Answer1 172.25.90.238 Answer2 129.49.23.177 
2021-04-09 16:13:19.173489 -0400 EDT DNS poisoning attempt
TXID 0xc798 Request www.medium.com
Answer1 162.159.152.4 162.159.153.4 Answer2 172.25.90.238 
2021-04-09 16:13:27.076168 -0400 EDT DNS poisoning attempt
TXID 0xe1fe Request www.cs.stonybrook.edu
Answer1 live-compscisbu.pantheonsite.io fe2.edge.pantheon.io 23.185.0.2 Answer2 172.25.90.238 
2021-04-09 16:13:33.780204 -0400 EDT DNS poisoning attempt
TXID 0x1114 Request www.tcpdump.org
Answer1 192.139.46.66 159.89.89.188 Answer2 172.25.90.238 
2021-04-09 16:13:49.619194 -0400 EDT DNS poisoning attempt
TXID 0xf936 Request www.gotowebinar.com
Answer1 13.90.213.204 Answer2 172.25.90.238 
2021-04-09 16:13:56.026009 -0400 EDT DNS poisoning attempt
TXID 0xeee6 Request www.gotomeeting.com
Answer1 wildcard-san.logmein.com.edgekey.net e15661.b.akamaiedge.net 96.7.74.73 96.7.74.43 Answer2 172.25.90.238


References:

1. https://pkg.go.dev/github.com/facebookgo/subset
2. https://github.com/google/gopacket/blob/master/examples/pcaplay/main.go
3. https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go


