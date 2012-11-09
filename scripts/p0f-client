#!/usr/bin/env python

import p0fclient
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-s", "--socket", dest="sock", default="/var/run/p0f.sock",
        help="UNIX domain socket where p0f is listening")
(options, args) = parser.parse_args()

p0f = p0fclient.P0fClient(options.sock)

for addr in args:
    info = None
    try:
        info = p0f.query(addr)
    except p0fclient.NoMatch:
        print "{0}: No match found".format(addr)
        continue
    print "{0}:".format(addr)
    print """    First seen: {first_seen!s}
    Last seen: {last_seen!s}
    Total connections: {total_conn}""".format(**info.__dict__)
    if info.os_name:
        print "    OS: {0} {1}".format(info.os_name, info.os_flavor)
        print "    OS match quality: {0}".format(
                (["normal", "fuzzy", "generic", "fuzzy and generic"])[info.os_match_q])
        if info.last_chg:
            print "    Last OS change: {0!s}".format(info.last_chg)
    if info.distance is not None:
        print "    Distance: {0}".format(info.distance)
    if info.uptime_min != 0:
        print "    Uptime: {0}:{1:02}:{2:02}, modulo {3} days".format(
                info.uptime_min / (60 * 24),
                (info.uptime_min / 60) % (60 * 24),
                info.uptime_min % 60,
                info.up_mod_days)
    if info.last_nat:
        print "    Last IP sharing: {0!s}".format(info.last_nat)
    if info.http_name:
        print "    HTTP app: {0} {1}".format(info.http_name, info.http_flavor)
        if info.bad_sw:
            print "    OS mismatch: {0}".format(info.bad_sw)
    if info.link_type:
        print "    Link type: {0}".format(info.link_type)
    if info.language:
        print "    Language: {0}".format(info.language)
