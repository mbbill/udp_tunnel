#!/usr/bin/env python
# Author Ming, Bai
import argparse
import json
import random
import select
import sha
import socket
import sys
import time
import pytun

################################
# tun <--> client [cmd port; data port0 ... data portn] <====> server [cmd port; data port0 ... data port n] <--> tun

################################
# Parse command line args
parser = argparse.ArgumentParser(description='UDP Tunnel, give --help for more info.')
parser.add_argument('--mode', help = 'Server mode (server or client)', required=True)
parser.add_argument('--sip', help = 'Server ip address')
parser.add_argument('--sport', type = int, help = 'Server port')
parser.add_argument('--snum', type = int, help = 'Number of listen ports, starting from port+1')
# client mode
parser.add_argument('--lip', help = 'Bind local ip address')
parser.add_argument('--lport', type = int, help = 'Server port')
parser.add_argument('--lnum', type = int, help = 'Number of listen ports, starting from port+1')
args = parser.parse_args()

mode = args.mode

sip = args.sip
sport = args.sport
snum = args.snum
lip = args.lip
lport = args.lport
lnum = args.lnum

if sip == None:
    print "--ip <address>"
    exit(-1)
if mode == "client" and lip == None:
    print "--lip <address>"
    exit(-1)
if sport == None:
    sport = 10000;
if snum == None:
    snum = 10
if snum < 1:
    print "num should >= 1"
    exit(-1)
if lport == None:
    lport = 20000;
if lnum == None:
    lnum = 10
if lnum < 1:
    print "lnum should >= 1"
    exit(-1)

def hash(passwd):
    salt = '!@#$%^&*(@#$%^&*(ERTYHGBNfiuwqpoif'
    digest = sha.new(passwd+salt).hexdigest()
    return digest

def encode(data):
    # simple xor encode to fool the g.f.w
    b = bytearray(data)
    for i in range(len(b)):
        b[i] ^= 1
    return str(b)

def print_hex(data):
    print "Data: " + str(len(data)) + " bytes"
    #print "Data: " + str(data)
    #print ':'.join(x.encode('hex') for x in data)

def tun_setup():
    tun = None
    if mode == "server":
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

def do_server():
    server = (sip, sport)
    cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmd_sock.setblocking(0)
    try:
        cmd_sock.bind(server)
    except socket.error, msg:
        print "Bind failed. Error: " + str(msg[0]) + " " + msg[1]
        sys.exit(1)

    # this tunnel
    fds = [cmd_sock]
    for port in range(sport+1,sport+1+snum):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        try:
            sock.bind((sip, port))
        except socket.error, msg:
            print "Bind failed. Error: " + str(msg[0]) + " " + msg[1]
            sys.exit(1)
        fds.append(sock)
    tunfd = tun_setup()
    fds.append(tunfd)

    print "Command port [" + str(sport) + "]"
    print "Data ports [" + str(sport+1) + "-" + str(sport+1+snum) + "]"
    print "Server running..."
    client_ip = None
    client_port = None
    client_num = None
    while True:
        readble,_,_ = select.select(fds,[],[])
        for fd in readble:
            if fd == cmd_sock:
                data, addr = fd.recvfrom(2048)
                jsondata = {'num':snum,'status':'OK'}
                datastr = json.dumps(jsondata)
                # verify
                try:
                    decoded = json.loads(data)
                except:
                    print "Command error."
                    continue
                client_num = int(decoded['num'])
                client_port = addr[1]
                if (client_num + client_port > 65535):
                    print "Port num error: " + client_num
                    continue
                client_ip = addr[0]
                # send back num
                fd.sendto(datastr,addr)
                print "Client connected: " + addr[0]
            elif fd == tunfd:
                # from tun
                #buf = tunfd.read(tunfd.mtu)
                buf = tunfd.read(2048)
                srnd = random.randint(1,snum)
                to_port = random.randint(client_port+1, client_port+client_num)
                to_sock = fds[srnd]
                to_sock.sendto(buf, (client_ip, to_port))
              	print "tun -> sock(" + str(client_ip) + " : " + str(client_port)
		print_hex(buf) 
            elif client_ip != None:
                data, addr = fd.recvfrom(2048)
                tunfd.write(data)
                print "sock(" + str(addr[0]) + " : " + str(addr[1]) + ") --> tun"
		print_hex(data) 
            else:
                data, addr = fd.recvfrom(2048)
                print 'packet dropped: ' + addr[0] + ':' + str(addr[1])


def do_client():
    cmd_addr = (lip, lport)
    cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmd_sock.setblocking(0)
    try:
        cmd_sock.bind(cmd_addr)
    except socket.error, msg:
        print "Bind failed. Error: " + str(msg[0]) + " " + msg[1]
        sys.exit(1)

    fds = [cmd_sock]
    for port in range(lport+1,lport+1+lnum):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        try:
            sock.bind((lip, port))
        except socket.error, msg:
            print "Bind failed. Error: " + str(msg[0]) + " " + msg[1]
            sys.exit(1)
        fds.append(sock)
    tunfd = tun_setup()
    fds.append(tunfd)

    print "Command port [" + str(lport) + "]"
    print "Data ports [" + str(lport+1) + "-" + str(lport+1+lnum) + "]"
    server_ip = sip
    server_port = sport
    server_num = None
    server_addr = (sip, sport)

    jsondata = {'num':lnum}
    datastr = json.dumps(jsondata)
    while True:
        print 'Connecting to: ' + server_ip + ':' + str(server_port)
        cmd_sock.sendto(datastr, server_addr)
        readble,_,_ = select.select([cmd_sock],[],[],5)
        if len(readble) != 0:
            data, addr = cmd_sock.recvfrom(2048)
            decoded = json.loads(data)
            server_num = int(decoded['num'])
            if decoded['status'] == 'OK':
                print 'Connected, server port num: ' + str(server_num)
                break

    while True:
        readble,_,_ = select.select(fds,[],[])
        for fd in readble:
            if fd == cmd_sock:
                data, addr = fd.recvfrom(2048)
                #heartbeat
                continue
            elif fd == tunfd:
                #from tun
                #buf = tunfd.read(tunfd.mtu)
                buf = tunfd.read(2048)
                lrnd = random.randint(1,lnum)
                to_port = random.randint(server_port+1, server_port+server_num)
                to_sock = fds[lrnd]
                to_sock.sendto(buf, (server_ip, to_port))
              	print "tun -> sock(" + str(server_ip) + " : " + str(to_port)
		print_hex(buf) 
            else:
                # from data socks
                data, addr = fd.recvfrom(2048)
                tunfd.write(data)
                print "sock(" + str(addr[0]) + " : " + str(addr[1]) + ") --> tun"
		print_hex(data) 

if mode == 'server':
    do_server()
else:
    do_client()

