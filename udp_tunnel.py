#!/usr/bin/env python
# Author Ming, Bai
from Crypto import Random
from Crypto.Cipher import AES
import argparse
import hashlib
import json
import pytun
import random
import select
import sha
import socket
import struct
import sys
import time

################################
# tun <--> client [cmd port; data port0 ... data portn] <====> server [cmd port; data port0 ... data port n] <--> tun

################################
# Parse command line args
parser = argparse.ArgumentParser(description='UDP Tunnel, give --help for more info.')
parser.add_argument('--mode', help = 'Server mode (server or client)', required=True)
parser.add_argument('--host', help = 'Server hostname or ip address')
parser.add_argument('--sport', type = int, help = 'Server port')
parser.add_argument('--snum', type = int, help = 'Number of listen ports, starting from port+1')
parser.add_argument('--passwd', help = 'Password, length must be multiple of 16')
# client mode
parser.add_argument('--lip', help = 'Bind local ip address')
parser.add_argument('--lport', type = int, help = 'Server port')
parser.add_argument('--lnum', type = int, help = 'Number of listen ports, starting from port+1')
parser.add_argument('--set-gw', help = 'Set default gateway to the tun dev')
args = parser.parse_args()

mode = args.mode

sport = args.sport
snum = args.snum
lip = args.lip
lport = args.lport
lnum = args.lnum
passwd = args.passwd

try:
    if args.host == None:
        print "what's the hostname?"
        exit(-1)
    sip = socket.gethostbyname(args.host)
except socket.error:
    print "Cannot resolv " + str(args.sip)
    exit(-1)

if mode == "client" and lip == None:
    print "--lip <address>"
    exit(-1)
if sport == None:
    sport = 10000;
if snum == None:
    snum = 1000 # has to modify limits.conf to allow more ports
if snum < 1:
    print "num should >= 1"
    exit(-1)
if lport == None:
    lport = 20000;
if lnum == None:
    lnum = 100
if lnum < 1:
    print "lnum should >= 1"
    exit(-1)
if passwd == None:
    print "No password?"
    exit(-1)
if len(passwd) < 16 or len(passwd)%16 != 0:
    print "Password length must be multiple of 16"
    exit(-1)

# setup route
#root@mbspi:/home/pi/udp_tunnel# route add -net 0.0.0.0 netmask 128.0.0.0 dev ctun
#root@mbspi:/home/pi/udp_tunnel# route add -net 128.0.0.0 netmask 128.0.0.0 dev ctun
#root@mbspi:/home/pi/udp_tunnel# route add -net 104.224.175.54 netmask 255.255.255.255 dev ppp0

def tun_setup(is_server):
    tun = None
    if is_server == True:
        tun = pytun.TunTapDevice("stun")
        tun.addr = "10.9.0.1"
        tun.dstaddr = "10.9.0.2"
    else:
        tun = pytun.TunTapDevice("ctun")
        tun.addr = "10.9.0.2"
        tun.dstaddr = "10.9.0.1"
    tun.netmask = "255.255.255.0"
    tun.mtu=1300
    tun.up()
    return tun


class AESCipher:
    def __init__( self, key ):
        self.BS = 16
        sha1obj = hashlib.sha1()
        sha1obj.update(key)
        self.key = sha1obj.hexdigest()[:16]

    def pad(self, raw):
        #two bytes length,+padded data
        lenbytes = struct.pack('<H', len(raw))
        padding = 'x' * (self.BS - (len(raw)+2)%self.BS)
        return lenbytes + raw + padding

    def unpad(self, data):
        datalen = struct.unpack('<H', data[:2])[0]
        return data[2:2+datalen]

    def encrypt(self, raw):
        raw = self.pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return iv+cipher.encrypt(raw)

    def decrypt(self, enc):
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return self.unpad(cipher.decrypt( enc[16:] ))


class udptun_server:
    def __init__(self, cipher, server_ip, server_port, server_num):
        self.cipher = cipher
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_num = server_num
        self.tunfd = None
        self.epoll = select.epoll()
        self.fno_to_fd = {}
        self.data_socks = []
        self.cmd_sock = None
        self.jsondata = json.dumps({'num':server_num,'status':'OK'})
        #current client info
        self.client_ip = None
        self.client_port = None
        self.client_num = None

    def tun_init(self):
        self.tunfd = tun_setup(True)

    def fd_init(self):
        cmd_addr = (self.server_ip, self.server_port)
        self.cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cmd_sock.setblocking(0)
        try:
            self.cmd_sock.bind(cmd_addr)
        except socket.error, msg:
            print "Socket Error: " + str(msg[0]) + " " + msg[1]
            return False
        for port in range(self.server_port+1, self.server_port+1+self.server_num):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(0)
            try:
                sock.bind((self.server_ip, port))
            except socket.error, msg:
                print "Socket Error: " + str(msg[0]) + " " + msg[1]
                return False
            self.data_socks.append(sock)
            self.epoll.register(sock.fileno(), select.EPOLLIN)
            self.fno_to_fd[sock.fileno()] = sock
        self.epoll.register(self.cmd_sock.fileno(), select.EPOLLIN)
        self.fno_to_fd[self.cmd_sock.fileno()] = self.cmd_sock
        self.epoll.register(self.tunfd.fileno(), select.EPOLLIN)
        self.fno_to_fd[self.tunfd.fileno()] = self.tunfd
        print "Command port [" + str(self.server_port) + "]"
        print "Data ports [" + str(self.server_port+1) + "-" + str(self.server_port+self.server_num) + "]"

    def serve(self):
        print "Server running..."
        while True:
            events = self.epoll.poll(30)
            if len(events) == 0:
                #connect test
                print "No data for 30s"
            for fileno, event in events:
                if fileno == self.cmd_sock.fileno():
                    data, addr = self.cmd_sock.recvfrom(2048)
                    data = self.cipher.decrypt(data)
                    # verify
                    try:
                        decoded = json.loads(data)
                    except:
                        print "Command error."
                        continue
                    self.client_num = int(decoded['num'])
                    self.client_port = addr[1]
                    if (self.client_num + self.client_port > 65535):
                        print "Port num error: " + self.client_num
                        continue
                    self.client_ip = addr[0]
                    # send back num
                    self.cmd_sock.sendto(self.cipher.encrypt(self.jsondata),addr)
                    print "Client connected: " + addr[0]
                elif fileno == self.tunfd.fileno(): # from tun
                    buf = self.tunfd.read(2048)
                    buf = self.cipher.encrypt(buf)
                    rnd = random.randint(0, self.server_num-1)
                    to_port = random.randint(self.client_port+1, self.client_port+self.client_num)
                    to_sock = self.data_socks[rnd]
                    to_sock.sendto(buf, (self.client_ip, to_port))
                    #print "tun -> sock(" + str(self.client_ip) + ":" + str(to_port) + ")"
                else: # from sock
                    if self.client_ip != None:
                        # connected
                        data, addr = self.fno_to_fd[fileno].recvfrom(2048)
                        data = self.cipher.decrypt(data)
                        self.tunfd.write(data)
                        #print "sock(" + str(addr[0]) + ":" + str(addr[1]) + ") --> tun"
                    else:
                        data, addr = self.fno_to_fd[fileno].recvfrom(2048)
                        data = self.cipher.decrypt(data)
                        print 'packet dropped: ' + addr[0] + ':' + str(addr[1])

    def run(self):
        self.tun_init();
        if self.fd_init() == False:
            return
        self.serve()



class udptun_client:
    def __init__(self, cipher, local_ip, local_port, local_num, server_ip, server_port):
        self.cipher = cipher
        self.local_ip = local_ip
        self.local_port = local_port
        self.local_num = local_num
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_num = None
        self.tunfd = None
        self.epoll = select.epoll()
        self.fno_to_fd = {}
        self.data_socks = []
        self.cmd_sock = None
        self.jsondata = json.dumps({'num':local_num})

    def tun_init(self):
        self.tunfd = tun_setup(False)

    def fd_init(self):
        cmd_addr = (self.local_ip, self.local_port)
        self.cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cmd_sock.setblocking(0)
        try:
            self.cmd_sock.bind(cmd_addr)
        except socket.error, msg:
            print "Socket Error: " + str(msg[0]) + " " + msg[1]
            return False
        for port in range(self.local_port+1, self.local_port+1+self.local_num):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(0)
            try:
                sock.bind((self.local_ip, port))
            except socket.error, msg:
                print "Socket Error: " + str(msg[0]) + " " + msg[1]
                return False
            self.data_socks.append(sock)
            self.epoll.register(sock.fileno(), select.EPOLLIN)
            self.fno_to_fd[sock.fileno()] = sock
        self.epoll.register(self.cmd_sock.fileno(), select.EPOLLIN)
        self.fno_to_fd[self.cmd_sock.fileno()] = self.cmd_sock
        self.epoll.register(self.tunfd.fileno(), select.EPOLLIN)
        self.fno_to_fd[self.tunfd.fileno()] = self.tunfd
        print "Command port [" + str(self.local_port) + "]"
        print "Data ports [" + str(self.local_port+1) + "-" + str(self.local_port+self.local_num) + "]"

    def connect(self):
        while True:
            print 'Connecting to: ' + self.server_ip + ':' + str(self.server_port)
            try:
                self.cmd_sock.sendto(self.cipher.encrypt(self.jsondata), (self.server_ip, self.server_port))
                readable,_,_ = select.select([self.cmd_sock],[],[],5)
                if len(readable) != 0:
                    data, addr = self.cmd_sock.recvfrom(2048)
                    data = self.cipher.decrypt(data)
                    decoded = json.loads(data)
                    self.server_num = int(decoded['num'])
                    if decoded['status'] == 'OK':
                        print 'Connected, server port num: ' + str(self.server_num)
                        break
            except socket.error, msg:
                print "Socket Error: " + str(msg[0]) + " " + msg[1]
                print "Sleep and retry"
                time.sleep(5)

    def transfer(self):
        try:
            while True:
                events = self.epoll.poll(30)
                if len(events) == 0:
                    #no data, test connection
                    #print "Hello?"
                    #hello = "Hello?"
                    #self.cmd_sock.sendto(self.cipher.encrypt(hello), (self.server_ip, self.server_port))
                    continue
                for fileno, event in events:
                    if fileno == self.cmd_sock:
                        data, addr = self.cmd_sock.recvfrom(2048)
                        data = self.cipher.decrypt(data)
                        continue
                    elif fileno == self.tunfd.fileno():
                        #from tun
                        buf = self.tunfd.read(2048)
                        buf = self.cipher.encrypt(buf)
                        rnd = random.randint(0, self.local_num-1)
                        to_port = random.randint(self.server_port+1, self.server_port+self.server_num)
                        to_sock = self.data_socks[rnd]
                        to_sock.sendto(buf, (self.server_ip, to_port))
                        #print "tun -> sock(" + str(self.server_ip) + ":" + str(to_port) + ")"
                    else:
                        # from data socks
                        data, addr = self.fno_to_fd[fileno].recvfrom(2048)
                        data = self.cipher.decrypt(data)
                        self.tunfd.write(data)
                        #print "sock(" + str(addr[0]) + ":" + str(addr[1]) + ") --> tun"
        except socket.error, msg:
            print "Socket Error: " + str(msg[0]) + " " + msg[1]
            return

    def run(self):
        self.tun_init()
        if self.fd_init() == False:
            return
        while True:
            self.connect()
            self.transfer()

cipher = AESCipher(passwd)
runner = None
if mode == 'server':
    runner = udptun_server(cipher, sip, sport, snum)
else:
    runner = udptun_client(cipher, lip, lport, lnum, sip, sport)

runner.run()
#import cProfile
#cProfile.run('runner.run()')


# vim: ts=4:sw=4:si:et 
