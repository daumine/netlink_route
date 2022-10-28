# -*- coding: utf-8 -*-
import ipaddress
from enum import IntEnum
import socket
import os
import struct


def array_to_mac_address(arr):
    return ":".join(["{:02X}".format(c) for c in arr])


def array_to_ipaddress(arr):
    return ipaddress.ip_address(arr).compressed


# defined in /usr/include/linux/netlink.h
class NLMSG_TYPE(IntEnum):
    NOOP  = 0x1
    ERROR = 0x2
    DONE  = 0x3
    OVERRUN = 0x4


# defined in /usr/include/linux/rtnetlink.h
class RTMGRP(IntEnum):
    LINK = 1
    IPV4_IFADDR = 0x10
    IPV6_IFADDR = 0x100


class RTM(IntEnum):
    NEWLINK = 16
    DELLINK = 17
    NEWADDR = 20
    DELADDR = 21


# defined in /usr/include/linux/if_link.h
class IFLA (IntEnum):
    ADDRESS = 1
    BROADCAST = 2
    IFNAME = 3
    MTU = 4
    LINK = 5
    QDISC = 6
    STATS = 7


# defined in /usr/include/net/if.h
class IFF(IntEnum):
    UP = 0x1
    BROADCAST = 0x2
    DEBUG = 0x4
    LOOPBACK = 0x8
    POINTTOPOINT = 0x10
    NOTRAILERS = 0x20
    RUNNING = 0x40
    NOARP = 0x80
    PROMISC = 0x100
    ALLMULTI = 0x200
    MASTER = 0x400
    SLAVE = 0x800
    MULTICAST = 0x1000
    PORTSEL = 0x2000
    AUTOMEDIA = 0x4000
    DYNAMIC = 0x8000


# defined in /usr/include/linux/if_addr.h
class IFA (IntEnum):
    ADDRESS = 1
    LOCAL = 2
    LABEL = 3
    BROADCAST = 4
    ANYCAST = 5
    CACHEINFO = 6
    FLAGS = 8


NLMSG_ALIGNTO = 4


def NLMSG_ALIGN(len):
    return (len + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)


NLMSGHDR_FORMAT = "=LHHLL"
NLMSG_HDRLEN = NLMSG_ALIGN(struct.calcsize(NLMSGHDR_FORMAT))


def NLMSG_LENGTH(len):
    return len + NLMSG_HDRLEN


class NLMSGHDR:
    FORMAT = NLMSGHDR_FORMAT

    def __init__(self, data):
        self.nlmsg_len, self.nlmsg_type, self.nlmsg_flags, self.nlmsg_seq, self.nlmsg_pid = struct.unpack(NLMSGHDR.FORMAT, data)


class NLMSG:
    def __init__(self, data: bytes):
        self.data = data
        self.nlmsghdr = None
        self.data_pos = 0

    @staticmethod
    def nlmsg_type(nlmsghdr):
        if nlmsghdr.nlmsg_type == NLMSG_TYPE.NOOP:
            return "NLMSG_NOOP"

        if nlmsghdr.nlmsg_type == NLMSG_TYPE.ERROR:
            return "NLMSG_ERROR"

        if nlmsghdr.nlmsg_type == NLMSG_TYPE.DONE:
            return "NLMSG_DONE"

        return f"NLMSG_{str(nlmsghdr.nlmsg_type)}"

    def process(self):
        self.nlmsghdr = NLMSGHDR(self.data[:NLMSG_HDRLEN])
        self.data_pos += NLMSG_HDRLEN
        print(NLMSG.nlmsg_type(self.nlmsghdr))

        if self.nlmsghdr.nlmsg_type == NLMSG_TYPE.NOOP:
            return

        if self.nlmsghdr.nlmsg_type == NLMSG_TYPE.ERROR:

            print("NLMSG Error")
            return

        if self.nlmsghdr.nlmsg_type == RTM.NEWLINK or self.nlmsghdr.nlmsg_type == RTM.DELLINK:
            if self.nlmsghdr.nlmsg_type == RTM.NEWLINK:
                print("New Link")
            elif self.nlmsghdr.nlmsg_type == RTM.DELLINK:
                print("Del Link")

            self.do_nlmsg_type_link()

        elif self.nlmsghdr.nlmsg_type == RTM.NEWADDR or self.nlmsghdr.nlmsg_type == RTM.DELADDR:
            if self.nlmsghdr.nlmsg_type == RTM.NEWADDR:
                print("New Addr")
            elif self.nlmsghdr.nlmsg_type == RTM.DELADDR:
                print("Del Addr")

            self.do_nlmsg_type_ipv4_addr()

    def do_nlmsg_type_link(self):
        data = self.data[self.data_pos:self.data_pos+16]
        family, if_type, index, flags, change = struct.unpack("=BxHiII", data)
        self.data_pos += 16

        if flags & IFF.UP:
            print("Device is UP")
        else:
            print("Device is Down")

        if flags & IFF.RUNNING:
            print("Device is running")
        else:
            print("Device is not running")

        print(f"family {family}, if_type {if_type}, index {index}, flags {flags}, change {change}")

        while self.data_pos < self.nlmsghdr.nlmsg_len:
            rta_len, rta_type = struct.unpack("=HH", self.data[self.data_pos:self.data_pos+4])

            if rta_len < 4:
                break

            data_len = rta_len - 4
            self.data_pos += 4
            rta_data = self.data[self.data_pos:self.data_pos+data_len]
            self.data_pos += NLMSG_ALIGN(data_len)

            s = f"rta_type: IFLA {rta_type}:"
            if rta_type == IFLA.ADDRESS:
                print(f"{s} address {array_to_mac_address(rta_data)}")
            elif rta_type == IFLA.BROADCAST:
                print(f"{s} broadcast {array_to_mac_address(rta_data)}")
            elif rta_type == IFLA.IFNAME:
                print(f"{s} ifname {rta_data[:data_len-1].decode()}")
            elif rta_type == IFLA.MTU:
                print(f"{s} mtu {int.from_bytes(rta_data, byteorder='little')}")
            elif rta_type == IFLA.LINK:
                print(f"{s} link {rta_data}")
            elif rta_type == IFLA.QDISC:
                print(f"{s} qdisc {rta_data[:data_len - 1].decode()}")
            elif rta_type == IFLA.STATS:
                print(f"{s} stats {rta_data}")
            else:
                print(f"{s} {rta_data}")

    def do_nlmsg_type_ipv4_addr(self):
        family, prefixlen, flags, scope, index = struct.unpack("=BBBBI", self.data[self.data_pos:self.data_pos+8])
        self.data_pos += 8

        print(f"family {family}, prefixlen {prefixlen}, flags {flags}, scope {scope}, index {index}")

        while self.data_pos < self.nlmsghdr.nlmsg_len:
            rta_len, rta_type = struct.unpack("=HH", self.data[self.data_pos:self.data_pos + 4])

            if rta_len < 4:
                break

            data_len = rta_len - 4
            self.data_pos += 4
            rta_data = self.data[self.data_pos:self.data_pos + data_len]
            self.data_pos += NLMSG_ALIGN(data_len)

            s = f"rta_type: IFA {rta_type}:"
            if rta_type == IFA.ADDRESS:
                print(f"{s} address {array_to_ipaddress(rta_data)}")
            elif rta_type == IFA.LOCAL:
                print(f"{s} local {array_to_ipaddress(rta_data)}")
            elif rta_type == IFA.LABEL:
                print(f"{s} label {rta_data[:data_len - 1].decode()}")
            elif rta_type == IFA.BROADCAST:
                print(f"{s} broadcast {array_to_ipaddress(rta_data)}")
            elif rta_type == IFA.ANYCAST:
                print(f"{s} anycast {array_to_ipaddress(rta_data)}")
            elif rta_type == IFA.CACHEINFO:
                print(f"{s} cacheinfo {rta_data}")
            elif rta_type == IFA.FLAGS:
                print(f"{s} flags {rta_data}")
            else:
                print(f"{s} {rta_data}")


def main():
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as s:
        s.bind((os.getpid(), RTMGRP.LINK | RTMGRP.IPV4_IFADDR | RTMGRP.IPV6_IFADDR))

        while True:
            NLMSG(s.recv(65535)).process()


if __name__ == '__main__':
    main()
