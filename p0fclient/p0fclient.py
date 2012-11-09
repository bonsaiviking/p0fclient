#!/usr/bin/env python

import socket
import struct
import ipaddr
from datetime import datetime

class CommError(RuntimeError):
    """A communications problem with p0f"""
    pass

class NoMatch(Exception):
    """p0f doesn't know about that IP"""
    pass

class HostInfo(object):
    """Holds all the information about a host, parsed from a p0f response"""
    def __init__(self):
        self.first_seen = None
        self.last_seen =  None
        self.total_conn = None
        self.uptime_min = None
        self.up_mod_days = None
        self.last_nat = None
        self.last_chg = None
        self.distance = None
        self.bad_sw = None
        self.os_match_q = None
        self.os_name = None
        self.os_flavor = None
        self.http_name = None
        self.http_flavor = None
        self.link_type = None
        self.language = None

class P0fClient(object):
    """Client for p0f API access over a UNIX domain socket"""
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(path)

    def parse_response(self, blob):
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
        h = HostInfo()
        h.first_seen = datetime.utcfromtimestamp(info[0])
        h.last_seen =  datetime.utcfromtimestamp(info[1])
        h.total_conn = info[2]
        h.uptime_min = info[3] or None
        h.up_mod_days = info[4] or None
        if info[5] != 0:
            h.last_nat = datetime.utcfromtimestamp(info[5])
        if info[6] != 0:
            h.last_chg = datetime.utcfromtimestamp(info[6])
        if info[7] != -1:
            h.distance = info[7]
        if info[8] != "\x00":
            h.bad_sw = info[8] # 1 means OS mismatch, 2 means very mismatched
        h.os_match_q = ord(info[9]) #0=normal, 1=fuzzy, 2=generic, 3=fuzzy and generic
        h.os_name = info[10].rstrip("\x00")
        h.os_flavor = info[11].rstrip("\x00")
        h.http_name = info[12].rstrip("\x00")
        h.http_flavor = info[13].rstrip("\x00")
        h.link_type = info[14].rstrip("\x00")
        h.language = info[15].rstrip("\x00")
        return h

    def query(self, ip):
        a = ipaddr.IPAddress(ip)
        self.sock.send("{magic}{type}{addr:\x00<16}".format(
            magic=struct.pack("@L",0x50304601),
            type=chr(a.version),
            addr=str(a.packed)
            ))
        return self.parse_response( self.sock.recv(232) )

if __name__ == '__main__':
    import sys
    import pprint
    p0f = P0fClient(sys.argv[1])
    try:
        pprint.pprint(p0f.query(sys.argv[2]).__dict__)
    except NoMatch:
        print "No match found"
