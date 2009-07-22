#!/bin/env python
"""IPv4 network calculation functions"""
#See terms of use in README and LICENSE

#dqtoi and itodq were taken from the pyNMS
#ipv4 module which is LGPL. (http://pynms.sourceforge.net)

import socket
import sys

def dqtoi(dq):
    """dqtoi(dotted-quad-string)
Return an integer value given an IP address as dotted-quad string. You can also
supply the address as a a host name. """
    s = buffer(socket.inet_aton(dq))
    return (ord(s[0]) << 24) + (ord(s[1]) << 16) + (ord(s[2]) << 8) + (ord(s[3]))
def itodq(addr):
    """itodq(int_address) (integer to dotted-quad)
    Return a dotted-quad string given an integer. """
    intval = int(addr) # might get an IPv4 object
    s = "%c%c%c%c" % (((intval >> 24) & 0x000000ff), ((intval & 0x00ff0000) >> 16),((intval & 0x0000ff00) >> 8), (intval & 0x000000ff))
    return socket.inet_ntoa(s)


def netmask_shorthand_to_full(short_hand):
    """Convert a shorthand netmask to a full dotted quad netmask

    example: "24" becomes "255.255.255.0"
    example: "32" becomes "255.255.255.255"

    see http://www.digipro.com/Papers/IP_Subnetting.shtml if you are
    unfamiliar with this shorthand.
    """
    short_hand = int(short_hand)
    binary_netmask = ""
    for x in range(1,33):
        if x <= short_hand:
            binary_netmask += "1"
        else:
            binary_netmask += "0"
    netmask = int(binary_netmask,2)
    netmask = itodq(netmask)
    return netmask
    
def ip_in_network(ip,network):
    """Figure out if the given IP address is in the given network

    IP should be an IPv4 dotted quad string like "192.168.1.1"
    network should be IP/netmask like
    "192.168.1.1/255.255.255.0" or "192.168.1.1/24"

    see http://www.digipro.com/Papers/IP_Subnetting.shtml if you are
    unfamiliar with the shorthand for netmasks.
    """
    try:
        net_parts = network.split("/")
        network_base = net_parts[0]
        netmask = net_parts[1]
        assert len(network_base.split(".")) == 4
        if len(netmask) <= 2:
            #netmask is in shorthand.. expand it
            assert int(netmask) >= 0 and int(netmask) <= 32
            netmask = netmask_shorthand_to_full(netmask)
        else:
            #Netmask better be a dotted quad otherwise
            #we'll raise an exception
            parts = netmask.split(".")
            assert len(parts) == 4
            for p in parts:
                assert int(p) >= 0 and int(p) <= 255
    except:
        sys.stderr.write("Invalid network specified in ip_in_range function: %s\n" % network)
        sys.exit(1)
    lowest_ip = itodq((dqtoi(network_base) & dqtoi(netmask)))
    highest_ip = itodq((dqtoi(network_base) & dqtoi(netmask) ) +  ~dqtoi(netmask) )
    #print "Netmask: %s (as an int: %s)" % (netmask,dqtoi(netmask))
    #print "lowest ip: %s (as an int: %s)" % (lowest_ip,dqtoi(lowest_ip))
    #print "highest ip: %s (as an int: %s)" % (highest_ip,dqtoi(highest_ip))
    
    if ip >= lowest_ip and ip <= highest_ip:
        return True
    else:
        return False
