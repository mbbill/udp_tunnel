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

################################
# let's say you connect to your server like this:
#
# [server address : server UDP port]  < ------ > [client address : client UDP port]
#
# Now, it becomes:
#
# [server address : server UDP port] <--> [server address : [.....a lot of udp ports....]] < -------- > [ client address : [ ... a lot of ports ...]]  <----> [client address : client UDP port]
#
# example:
# OVPN(10.2.3.4:1234) <-> [this_script(10.2.3.4:[2000-3000])] <----> [this_script(192.1.1.2:5000-6000) - [port]] <-> [OVPN_CLIENT(192.1.1.2)]
#      ^sip     ^sport                           ^lport(lnum)
# for client
#                                      ^csip     ^csport(cspnum)                            ^clport(cspnum) ^cport

################################
# Parse command line args
parser = argparse.ArgumentParser(description='UDP Tunnel, give --help for more info.')
parser.add_argument('--mode', help = 'Server mode (server or client)', required=True)
parser.add_argument('--passwd', help = 'Password', required=True)
# Server mode arguments
parser.add_argument('--sip', help = 'Server ip address')
parser.add_argument('--sport', type = int, help = 'Server port')
parser.add_argument('--lport', type = int, help = 'Listen port start')
parser.add_argument('--lnum', type = int, help = 'Number of listen ports, starting from <lport>')
# Client mode arguments
parser.add_argument('--csip', help = 'Tunnel server address')
parser.add_argument('--csport', type = int, help = 'Tunnel server starting port')
parser.add_argument('--cspnum', type = int, help = 'Number of ports, starting from <csport>')
parser.add_argument('--clport', type = int, help = 'Client starting port')
parser.add_argument('--cport', type = int, help = 'Client listen port')
args = parser.parse_args()

passwd = args.passwd
mode = args.mode
if args.mode == 'server':
    sip = args.sip
    sport = args.sport
    lport = args.lport
    lnum = args.lnum
    if sip == None:
        print "--sip <address>"
        exit(-1)
    if sport == None:
        print "--sport <port>"
        exit(-1)
    if lport == None:
        lport = 31000 #default
    if lnum == None:
        lnum = 10
    if lnum < 2:
        print "lnum should >= 2"
        exit(-1)
else:
    csip = args.csip
    csport = args.csport
    cspnum = args.cspnum
    clport = args.clport
    cport = args.cport
    if csip == None:
        print "--csip <address>"
        exit(-1)
    if csport == None:
        csport = 31000
    if cspnum == None:
        cspnum = 10
    if cspnum < 2:
        print "cspnum should >= 2"
        exit(-1)
    if clport == None:
        clport = 41000
    if cport == None:
        cport = 21000

# check args

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

def do_server():
    verified_addr = None
    # Everytime we receive a packet, write down its port,
    # therefore when sending packets back we can reuse them, workaround for NAT
    used_socks = []
    used_ports = []
    # external server
    ext_server = (sip,sport)
    ext_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ext_sock.setblocking(1)
    ext_sock.bind(('',0))
    # this tunnel
    socks = []
    cmd_sock = None
    cmd_addr = None
    for port in range(lport,lport+lnum):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(1)
        addr = ('',port)
        sock.bind(addr)
        socks.append(sock)
        if (port == lport):
            cmd_sock = sock # user the 1st sock to pass command
    socks.append(ext_sock)

    rx = 0
    tx = 0
    print 'Server listening on port [' + str(lport) + '-' + str(lport+lnum-1) + ']'
    while True:
        readble,_,_ = select.select(socks,[],[])
        for sock in readble:
            data, addr = sock.recvfrom(2048)
            if sock == cmd_sock:
                # verify
                try:
                    decoded = json.loads(data)
                except:
                    print "Command error."
                    continue
                if decoded['passwd'] == hash(passwd):
                    verified_addr = addr[0]
                    sock.sendto('OK',addr)
                    cmd_addr = addr
                    used_ports = [] # clear logged connections
                    used_socks = []
                    rx = 0
                    tx = 0
                    print "Client connected: " + addr[0]
                    continue
            elif sock == ext_sock:
                if verified_addr != None:
                    from_sock = random.randint(1,lnum-1)
                    used_len = len(used_socks)
                    if used_len != 0:
                        # pick a used socket
                        rnd = random.randint(0, used_len-1)
                        to_sock = used_socks[rnd]
                        to_port = used_ports[rnd]
                    else:
                        print "Client please talk first."
                        continue
                    to_sock.sendto(encode(data), (verified_addr, to_port))
                    tx += 1
                    print str(to_sock.getsockname()[1]) + ' -> ' + str(to_port) + ' tx: ' + str(tx)
            elif verified_addr != None: #verified
                if not sock in used_socks:
                    used_socks.append(sock)
                    used_ports.append(addr[1])
                ext_sock.sendto(encode(data),ext_server)
                rx += 1
                print str(sock.getsockname()[1]) + ' <- ' + str(addr[1]) + ' rx: ' + str(rx)
            else:
                print 'packet dropped: ' + addr[0] + ':' + str(addr[1])


def do_client():
    client_addr = None
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.setblocking(1)
    client_sock.bind(('',cport))
    print "Listening on port " + str(cport)

    socks = []
    cmd_sock = None
    for port in range(clport, clport+cspnum):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(1)
        addr = ('',port)
        sock.bind(addr)
        socks.append(sock)
        if port == clport:
            cmd_sock = sock # user the 1st sock to pass command
    socks.append(client_sock)

    jsondata = {'passwd':hash(passwd), 'port':clport,'portnum':cspnum}
    datastr = json.dumps(jsondata)
    while True:
        print 'Connecting to: ' + csip + ': [' + str(csport) + '-' + str(csport+cspnum-1) + ']'
        cmd_sock.sendto(datastr, (csip,csport))
        readble,_,_ = select.select([cmd_sock],[],[],5)
        if len(readble) != 0:
            data, addr = cmd_sock.recvfrom(2048)
            if data == 'OK':
                print 'Connected.'
                break

    rx = 0
    tx = 0
    while True:
        readble,_,_ = select.select(socks,[],[])
        for sock in readble:
            data, addr = sock.recvfrom(2048)
            if sock == client_sock:
                rnd = random.randint(1,cspnum-1)
                from_sock = socks[rnd]
                to_port = csport+rnd
                from_sock.sendto(encode(data), (csip, to_port))
                client_addr = addr
                tx += 1
                print str(from_sock.getsockname()[1]) + ' -> ' + str(to_port) + ' tx: ' + str(tx)
            elif client_addr != None:
                client_sock.sendto(encode(data), client_addr)
                rx += 1
                print str(sock.getsockname()[1]) + ' <- ' + str(addr[1]) + ' rx: ' + str(rx)
            else:
                print 'packet dropped: ' + addr[0] + str(addr[1])

    
if mode == 'server':
    do_server()
else:
    do_client()

