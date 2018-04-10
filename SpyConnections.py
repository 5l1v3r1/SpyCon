import sys
try:
 from impacket import ImpactDecoder
except:
	print("[!] Error The [impacket] library Is Not Install ! \n[#] Please Install It!\n[>] Usage This Command:> pip install impacket \n[$] And Try Again")
	exit(1)
try:
   import pcapy
except:
       print("[!] Error The [pcapy] library Is Not Install ! \n[#] Please Install It!\n[>] Usage This Command:> pip install pcapy \n[$] And Try Again")
       exit(1)

if len(sys.argv) !=2:
	print("\033[33m[#] Usage python SpyConnections.py <interface> \033[0m")
	exit(1)
iface = sys.argv[1]
def sniff(hdr,data):
    decoder = ImpactDecoder.EthDecoder()
    eth_pack = decoder.decode(data)
    ip_hdr = eth_pack.child()
    tcp_hdr = ip_hdr.child()
    src_ip = ip_hdr.get_ip_src()
    dst_ip = ip_hdr.get_ip_dst()
    print("[!>] New Connection found[ {} ---> {} ]".format(src_ip,dst_ip))
try:
 print("\n[+] Sniffer Connections Start [+]\n")

 sniffer = pcapy.open_live(iface,1500,1,100)
 sniffer.loop(0,sniff)
except KeyboardInterrupt:
		print("[$] Stoping Sniffer....")
                exit(1)


##############################################################
##################### 		     #########################
#####################   END OF TOOL  #########################
#####################                #########################
##############################################################
#This Tool by Oseid Aldary
#Have a nice day :)
#GoodBye
