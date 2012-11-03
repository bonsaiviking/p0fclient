#!/usr/bin/env python

import socket
import struct
import ipaddr
from datetime import datetime

class CommError(RuntimeError):
    pass

class NoMatch(Exception):
    pass

class HostInfo(object):
    def __init__(self, blob):
        if struct.unpack_from("@L", blob)[0] != 0x50304602:
            raise CommError, "Not a p0f response"
        status = struct.unpack_from("@L", blob, 4)[0]
        if status == 0x00:
            raise CommError, "Bad query"
        elif status == 0x20:
            raise NoMatch
        elif status != 0x10:
            raise CommError, "Unknown status"
        info = struct.unpack_from("7L H 2c 32s 32s 32s 32s 32s 32s", blob, 8)
        self.first_seen = datetime.utcfromtimestamp(info[0])
        self.last_seen =  datetime.utcfromtimestamp(info[1])
        self.total_conn = info[2]
        self.uptime_min = info[3]
        self.up_mod_days = info[4]
        if info[5] != 0:
            self.last_nat = datetime.utcfromtimestamp(info[5])
        if info[6] != 0:
            self.last_chg = datetime.utcfromtimestamp(info[6])
        if info[7] != -1:
            self.distance = info[7]
        if info[8] != "\x00":
            self.bad_sw = info[8] # 1 means OS mismatch, 2 means very mismatched
        self.os_match_q = ord(info[9]) #0=normal, 1=fuzzy, 2=generic, 3=fuzzy and generic
        self.os_name = info[10].rstrip("\x00")
        self.os_flavor = info[11].rstrip("\x00")
        self.http_name = info[12].rstrip("\x00")
        self.http_flavor = info[13].rstrip("\x00")
        self.link_type = info[14].rstrip("\x00")
        self.language = info[15].rstrip("\x00")

class P0fClient(object):
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(path)

    def query(self, ip):
        a = ipaddr.IPAddress(ip)
        self.sock.send("{magic}{type}{addr:\x00<16}".format(
            magic=struct.pack("@L",0x50304601),
            type=chr(a.version),
            addr=str(a.packed)
            ))
        return HostInfo( self.sock.recv(232) )

if __name__ == '__main__':
    import sys
    import pprint
    p0f = P0fClient(sys.argv[1])
    try:
        pprint.pprint(p0f.query(sys.argv[2]).__dict__)
    except NoMatch:
        print "No match found"
