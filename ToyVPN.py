from __future__ import print_function
from __future__ import unicode_literals

import os
import sys
import time
import struct
import socket
import base64
from fcntl import ioctl
from select import select
from threading import Thread
from ipaddress import ip_network

PASSWORD = b'4fb88ca224e'

MTU = 1400
BUFFER_SIZE = 4096
KEEPALIVE = 10
DEBUG = True
BIND_ADDRESS = '0.0.0.0',2003
NETWORK = '10.0.0.0/24'

IPRANGE = list(map(str,ip_network(NETWORK)))[1:]
LOCAL_IP = IPRANGE.pop(0)

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002

def createTunnel(tunName='tun%d', tunMode=IFF_TUN):
    tunfd = os.open("/dev/net/tun", os.O_RDWR)
    ifn = ioctl(tunfd, TUNSETIFF, struct.pack(b"16sH", tunName.encode(), tunMode))
    tunName = ifn[:16].decode().strip("\x00")
    return tunfd, tunName

def startTunnel(tunName, localIP, peerIP):
    os.popen('ifconfig %s %s dstaddr %s mtu %s up' %
             (tunName, localIP, peerIP, MTU)).read()
    
def encode_data(data):
    # 使用Base64对数据进行编码
    return base64.b64encode(data)

def decode_data(data):
    # 解码Base64数据
    return base64.b64decode(data)
    
class VPN():
    def __init__(self, mode, remote_address=None):
        self.mode = mode
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(5)
        self.readables = [self.udp]
        self.sessions = []
        if self.mode == "client":
            self.to = remote_address
        elif self.mode == "server":
            self.udp.bind(BIND_ADDRESS)
            print('Server listen on %s:%s...' % BIND_ADDRESS)
        else:
            raise ValueError("The mode must be either 'client' or 'server'")

    # Client functions
    def keepalive(self):
        def _keepalive(udp, to):
            while True:
                time.sleep(KEEPALIVE)
                udp.sendto(b'\x00', to)
        k = Thread(target=_keepalive, args=(self.udp, self.to), name='keepalive')
        k.setDaemon(True)
        k.start()

    def login(self):
        self.udp.sendto(PASSWORD,self.to)
        try:
            data,addr = self.udp.recvfrom(BUFFER_SIZE)
            data = decode_data(data)
            tunfd,tunName = createTunnel()
            localIP,peerIP = data.decode().split(';')
            print('Local ip: %s\tPeer ip: %s' % (localIP,peerIP))
            startTunnel(tunName,localIP,peerIP)
            return tunfd
        except socket.timeout:
            return False

    # Server functions
    def getTunByAddr(self, addr):
        for i in self.sessions:
            if i['addr'] == addr: return i['tunfd']
        return -1

    def getAddrByTun(self, tunfd):
        for i in self.sessions:
            if i['tunfd'] == tunfd: return i['addr']
        return -1

    def createSession(self, addr):
        tunfd, tunName = createTunnel()
        tunAddr = IPRANGE.pop(0)
        startTunnel(tunName, tunAddr)
        self.sessions.append(
            {
                'tunName': tunName, 'tunfd': tunfd, 'addr': addr,
                'tunAddr': tunAddr, 'lastTime': time.time()
            }
        )
        self.readables.append(tunfd)
        reply = '%s;%s' % (tunAddr, LOCAL_IP)
        self.udp.sendto(reply.encode(), addr)

    def delSessionByTun(self, tunfd):
        if tunfd == -1: return False
        for i in self.sessions:
            if i['tunfd'] == tunfd:
                self.sessions.remove(i)
                IPRANGE.append(i['tunAddr'])
        self.readables.remove(tunfd)
        os.close(tunfd)
        return True

    def updateLastTime(self, tunfd):
        for i in self.sessions:
            if i['tunfd'] == tunfd:
                i['lastTime'] = time
            time()

    def cleanExpireTun(self):
        while True:
            for i in self.sessions:
                if (time.time() - i['lastTime']) > 60:
                    self.delSessionByTun(i['tunfd'])
                    if DEBUG: print('Session: %s:%s expired!' % i['addr'])
            time.sleep(1)

    def auth(self, addr, data, tunfd):
        if data == b'\x00':
            if tunfd == -1:
                self.udp.sendto(b'r', addr)
            else:
                self.updateLastTime(tunfd)
            return False
        if data == b'e':
            if self.delSessionByTun(tunfd):
                if DEBUG: print("Client %s:%s is disconnect" % addr)
            return False
        if data == PASSWORD:
            return True
        else:
            if DEBUG: print('Clinet %s:%s connect failed' % addr)
            return False

    # Main function
    def run_forever(self):
        if self.mode == "server":
            cleanThread = Thread(target=self.cleanExpireTun)
            cleanThread.daemon = True
            cleanThread.start()

        if self.mode == "client":
            print('Start connect to server...')
            tunfd = self.login()
            if not tunfd:
                print("Connect failed!")
                sys.exit(0)
            print('Connect to server successful')
            self.keepalive()
            self.readables.append(tunfd)

        while True:
            try:
                readab = select(self.readables, [], [], 10)[0]
            except KeyboardInterrupt:
                self.udp.sendto(b'e', self.to)
                raise KeyboardInterrupt
            for r in readab:
                if r == self.udp:
                    data, addr = self.udp.recvfrom(BUFFER_SIZE)
                    data = decode_data(data)

                    if self.mode == "client":
                        try:
                            os.write(tunfd, data)
                        except OSError:
                            if data == b'r':
                                os.close(tunfd)
                                self.readables.remove(tunfd)
                                print('Reconnecting...')
                                tunfd = self.login()
                                self.readables.append(tunfd)
                            continue
                    elif self.mode == "server":
                        try:
                            tunfd = self.getTunByAddr(addr)
                            try:
                                os.write(tunfd, data)
                            except OSError:
                                if not self.auth(addr, data, tunfd): continue
                                self.createSession(addr)
                                if DEBUG: print('Clinet %s:%s connect successful' % addr)
                        except OSError:
                            continue
                else:
                    data = os.read(r, BUFFER_SIZE)
                    data = encode_data(data)
                    addr = self.getAddrByTun(r)
                    self.udp.sendto(data, addr)
                    if DEBUG: print(now() + 'to      (%s:%s)' % addr, data[:10])


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in ["client", "server"]:
        print('Usage: %s mode [remote_ip] [remote_port]' % sys.argv[0])
        print('mode should be either "client" or "server"')
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "client":
        if len(sys.argv) < 4:
            print('Usage: %s client remote_ip remote_port' % sys.argv[0])
            sys.exit(1)
        remote_address = sys.argv[2], int(sys.argv[3])
        VPN(mode, remote_address).run_forever()
    elif mode == "server":
        VPN(mode).run_forever()
