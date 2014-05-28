#!/usr/bin/env python
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
#                                      ^csip     ^csport(cspnum)                            ^clport(clpnum) ^cport

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
parser.add_argument('--clpnum', type = int, help = 'Number of ports, starting from <clport>')
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
        lnum = 1000
else:
    csip = args.csip
    csport = args.csport
    cspnum = args.cspnum
    clport = args.clport
    clpnum = args.clpnum
    cport = args.cport
    if csip == None:
        print "--csip <address>"
        exit(-1)
    if csport == None:
        csport = 31000
    if cspnum == None:
        cspnum = 1000
    if clport == None:
        clport = 41000
    if clpnum == None:
        clpnum = 1000
    if cport == None:
        cport = 21000

# check args

def hash(passwd):
    salt = '!@#$%^&*(@#$%^&*(ERTYHGBNfiuwqpoif'
    digest = sha.new(passwd+salt).hexdigest()
    return digest

def do_server():
    verified_addr = None
    verified_port = None
    verified_portnum = None
    # external server
    ext_server = (sip,sport)
    ext_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ext_sock.setblocking(0)
    ext_sock.bind(('',0))
    # this tunnel
    socks = [ext_sock]
    cmd_sock = None
    for port in range(lport,lport+lnum):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        addr = ('',port)
        sock.bind(addr)
        socks.append(sock)
        if (port == lport):
            cmd_sock = sock # user the 1st sock to pass command

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
                    verified_port = decoded['port']
                    verified_portnum = decoded['portnum']
                    sock.sendto('OK',addr)
                    print "Client connected: " + addr[0]
                    continue
            elif sock == ext_sock:
                if verified_addr != None:
                    socks[random.randint(1,lnum-2)].sendto(data,
                            (verified_addr,random.randint(verified_port+1,
                                verified_port+verified_portnum-2)))
            elif verified_addr != None: #verified
                    ext_sock.sendto(data,ext_server)
            else:
                print 'packet dropped: ' + addr[0] + ':' + str(addr[1])


def do_client():
    client_addr = None
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.setblocking(0)
    client_sock.bind(('',cport))
    print "Listening on port " + str(cport)

    socks = [client_sock]
    cmd_sock = None
    for port in range(clport, clport+clpnum):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        addr = ('',port)
        sock.bind(addr)
        socks.append(sock)
        if port == clport:
            cmd_sock = sock # user the 1st sock to pass command

    jsondata = {'passwd':hash(passwd), 'port':clport,'portnum':clpnum}
    datastr = json.dumps(jsondata)
    while True:
        print 'Connecting to: ' + csip + ':' + str(csport)
        cmd_sock.sendto(datastr, (csip,csport))
        readble,_,_ = select.select([cmd_sock],[],[],5)
        if len(readble) != 0:
            data, addr = cmd_sock.recvfrom(2048)
            if data == 'OK':
                print 'Connected.'
                break

    while True:
        readble,_,_ = select.select(socks,[],[])
        for sock in readble:
            data, addr = sock.recvfrom(2048)
            if sock == client_sock:
                socks[random.randint(1,clpnum-2)].sendto(data,
                        (csip,random.randint(csport+1,csport+cspnum-2)))
                client_addr = addr
            elif client_addr != None:
                    client_sock.sendto(data, client_addr)
            else:
                print 'packet dropped: ' + addr[0] + str(addr[1])

    
if mode == 'server':
    do_server()
else:
    do_client()

