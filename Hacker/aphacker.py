#-*- coding:utf-8 –*-
import sys
import struct
from scapy.all import *
import itamae.radiotap as rtap
import time

aps = []
aps1 = []
def get_time_stamp():
    ct = time.time()
    local_time = time.localtime(ct)
    data_head = time.strftime("%Y-%m-%d %H:%M:%S", local_time)
    data_secs = (ct - long(ct)) * 1000
    time_stamp = "%s.%03d" % (data_head, data_secs)
    return time_stamp

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            	if pkt.addr2 not in aps:
                    aps.append(pkt.addr2)
                    #pkt.show()
                    #pkt.notdecoded.encode('HEX')
                    head = rtap.parse(str(pkt[0]))
                    #print sig
                    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
                    if re.search('privacy', cap):
    				    a = 'Time:%s\tEncryption：Yes\tMAC:%s\tSSID:%s\tSSI:%s'%(get_time_stamp(),pkt.addr2, pkt.info,head['antsignal'])
    				    #with open('test.txt', 'a+') as t:
    				    #t.write(a+'\n')
    				    print a
                    else:
    				    b = 'Time:%s\tEncryption：Yes\tMAC:%s\tSSID:%s'%(get_time_stamp(),pkt.addr2, pkt.info)
    				    #with open('test.txt', 'a+') as t:
    				    #t.write(b+'\n')
    				    print b

        elif  pkt.type == 0 and pkt.subtype == 4:
            if '%s%s'%(pkt.addr2, pkt.info) not in aps1:
                    aps1.append('%s%s'%(pkt.addr2, pkt.info))
                    head = rtap.parse(str(pkt[0]))
                    print 'Time:%s\tMAC:%s\tSSID:%s\tSSI:%s'%(get_time_stamp(),pkt.addr2, pkt.info,head['antsignal'])

sniff(iface = 'wlan0mon', prn = PacketHandler)
