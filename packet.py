#!/bin/env python
#See terms of use in README and LICENSE
"""An object oriented abstraction of an ethernet packet.

Packet is the baseclass for all ethernet packets.

IPpacket and TCPpacket are subclasses that are encapsulated
inside of Packet objects. (for example, if the packet is a
TCP/IP packet then there will be IPpacket and TCPpacket objects
inside of the Packet object automatically when it is created.

In general, you won't use the subclasses IPpacket and TCPpacket
on their own. Rather, always instantiate the Packet object
and you will gain the IPpacket and TCPpacket automatically
if they exist in the original Ethernet packet data.

UDP packets are yet to be implemented."""

import socket
import struct

class Packet:
    """A representation of a generic Ethernet packet"""

    def __init__(self, data):
        self.packet = data
        self.sourceMAC = self.__extract_source_MAC()
        self.destinationMAC = self.__extract_destination_MAC()

        #According to the ethernet specification at :
        #http://en.wikipedia.org/wiki/Ethernet, the encapsulated data starts
        #at byte 14 (starting with 0)        
        self.payload = self.packet[14:]
        
        #Attempt to extract any sub-protocol packets:
        #IPv4:
        self.__extract_IP()
    def __extract_IP(self):
        """Attempt to extract an IPv4 packet if one exists"""
        #The IPv4 specification says that there is an EtherType attribute in
        #bytes 13-14 (positions 11 and 13 in python)
        #... if that Ethertype is 08 00, then we have an IP packet
        if self.packet[12:14] == "\x08\x00":
            self.IPpacket = IP_Packet(self.payload)
        else:
            self.IPpacket = None

    def __extract_source_MAC(self):
        """Extract and set the source MAC address"""
        #The source address is the second six bytes
        mac = ""
        for m in range(0,6):
            mac += pretty_hex(hex(ord(self.packet[6+m])))
            if m != 5: mac += ":"
        return mac
    
    def __extract_destination_MAC(self):
        """Extract and set the destination MAC address"""
        #The destiniation address is the first six bytes
        mac = ""
        for m in range(0,6):
            mac += pretty_hex(hex(ord(self.packet[m])))
            if m != 5: mac += ":"
        return mac
    
class IP_Packet:
    """A representation of an IPv4 packet"""
    def __init__(self,data):
        self.packet = data
        self.destination_address = self.__extract_destination_address()
        self.source_address = self.__extract_source_address()
        #According to the IPv4 specification at:
        #http://www.ietf.org/rfc/rfc0791.txt
        #The number of 32 bit words in the header can be found in the
        #last four bits of the first byte (byte 0).
        #Because it represents the number of 32 bit words in the packet,
        #we multiply by 4 to get the byte offset of the data contained in
        #the packet.
        header_length = (ord(self.packet[0]) & 0x0f) * 4
        self.payload = self.packet[header_length:]
        #Attempt to extract any subprotocol packets
        #TCP:
        self.__extract_TCP()

    def __extract_source_address(self):
        """Extract the source IP Address"""
        #The source IP is in bytes 13-16
        bytes = self.packet[12:16]
        ip=""
        for b in range(0,4):
            ip += str(ord(bytes[b]))
            if b != 3:
                ip += "."
        return ip
    
    def __extract_destination_address(self):
        """Extract the destination IP Address"""
        #The destination IP is in bytes 17-20
        bytes = self.packet[16:20]
        ip=""
        for b in range(0,4):
            ip += str(ord(bytes[b]))
            if b != 3:
                ip += "."
        return ip
    
    def __extract_TCP(self):
        """Attempt to extract a TCP packet if one exists"""
        #According to the TCP specification at:
        #http://www.ietf.org/rfc/rfc0793.txt
        #The 10th byte represents the subprotocol contained in the packet.
        #According to RFC790: http://www.ietf.org/rfc/rfc0790.txt
        #The number for TCP is 6
        if ord(self.packet[9]) == 6:
            self.TCPpacket = TCP_Packet(self.payload)
        else:
            self.TCPpacket = None
    
class TCP_Packet:
    """A representation of a TCP Packet"""
    def __init__(self,data):
        self.packet = data
        self.source_port = self.__extract_source_port()
        self.destination_port = self.__extract_destination_port()
        #According to the TCP specification at:
        #http://www.ietf.org/rfc/rfc0793.txt
        #The number of 32 bit words in the TCP header is found at the first
        #four bits of byte 12 (byte count starts at 0)
        #Again we multiply by four to get the byte offset.

        #this calculation is performed similar to the IP header offset,
        #however since we are dealing with the FIRST four bits of the
        #byte we also need to shift the bits to the lowest order,
        #which is 4 bits to the right (the '>> 4' part)
        #This complexity is the result of that fact that we cannot address
        #a single bit, but rather an entire byte at a time.
        tcp_offset = ((ord(self.packet[12]) & 0xf0) >> 4) * 4

        self.payload = self.packet[tcp_offset:]
    def __extract_source_port(self):
        #Source port is in the first two bytes
        return socket.ntohs(struct.unpack('H',self.packet[0:2])[0])
    def __extract_destination_port(self):
        #Destination port is in the second two bytes (3 and 4)
        return socket.ntohs(struct.unpack('H',self.packet[2:4])[0])


def pretty_hex(hex_string):
    """Transform a string like '0x6' to '06'"""
    str=hex_string[2:]
    if len(str) == 1:
        str = "0" + str
    return str.upper()
