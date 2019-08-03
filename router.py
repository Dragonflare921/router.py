# Simple IPv4 router implementation in python 2.7
# Intended for use with supplied mininet config
#
# Brandon Warner
# @dragonflare921
# dragonflare921@gmail.com
#
# TODO (Dragon): needs a bit of work to get from this 1.0 to a cleaner working state
#                1. write up a mininet config that sets up a network that can
#                   be added to this repo
#                2. resolve the bugs with getting a response
#                3. actually implement the ARP cache


import socket
import struct
import sys
import threading
import time
import binascii
import string
from ctypes import create_string_buffer

from eth import *
from ip import *
from arp import *
from util import *


# global ARP cache
ARPdict = dict()    # TODO (Dragon): MAKE A MUTEX

# using static
# these are all the other hosts
ARPdict[socket.inet_aton("192.168.1.100")] = 0x000000001100
ARPdict[socket.inet_aton("192.168.1.101")] = 0x000000001200
ARPdict[socket.inet_aton("192.168.2.100")] = 0x000000002100
ARPdict[socket.inet_aton("192.168.2.101")] = 0x000000002200
ARPdict[socket.inet_aton("192.168.3.100")] = 0x000000003100
ARPdict[socket.inet_aton("192.168.3.101")] = 0x000000003200

# these are for the router interfaces
ARPdict[socket.inet_aton("192.168.1.1")] = 0x000000000001
ARPdict[socket.inet_aton("192.168.2.1")] = 0x000000000002
ARPdict[socket.inet_aton("192.168.3.1")] = 0x000000000003
  

# worker thread that manages the TTL for ARP cache entries
class ARPTTLThread(threading.Thread):
  global ARPdict
  kill = None
  maxTTL = None
  
  def __init__(self):
    threading.Thread.__init__(self)
    self.kill = False
    
  def run(self):
    while not self.kill:
      # TODO (Dragon): SET UP A MUTEX FOR THIS
      for e in ARPdict:   # go over the whole cache checking TTL
        if e[1] <= 0:     # remove the entry if TTL ran out
          del e
        else:             # otherwise decrement the TTL
          e[1] -= 1
      time.sleep(1)   # sleep a second

# worker thread that handles incoming packets on an interface
class IfaceThread(threading.Thread):
  global ARPdict
  sock = None
  kill = None
  
  def __init__(self, s):
    threading.Thread.__init__(self)
    self.sock = s
    self.kill = False
    self.sock.settimeout(.1)
    self.kernel_routes = []
    
    # this is kinda dirty but only runs when we make the object
    # open up the routing table and save the routes for later use
    routesFD = open("/proc/net/route", 'r')
    next(routesFD)  # skip the table header
    i = 0
    for line in routesFD:
      j = 0
      ifField = ""
      for field in line.split("\t"):
        if j == 0:      # interface field 
          ifField = field
          #print "[DBUG]: found iface " + ifField
        elif j == 1:    # destination field
          dest = swap32(int(field, 16))  # routes file stores it LE
          
          macFD = open("/sys/class/net/" + ifField + "/address")    # open the sysfs file for the corresponding interface
          ifMacStr = macFD.readline()
          ifMacStr = string.strip(ifMacStr, "\n")
          ifMacNum = deMACify(ifMacStr)
          macFD.close()     # close the sysfs for the iface MAC
          
          self.kernel_routes.append((ifField, dest, ifMacNum))
          break         # dont need any more than those fields per line
        j += 1
      i += 1
    
    routesFD.close()
    
  def run(self):
    while not self.kill:
      try:
        data = self.sock.recvfrom(65535)
        
        ethpack = ETHPacket()
        
        ethpack.unpack(data[0])
        
        # gross, but, drop any packet from ourselves to avoid loops
        # hard assumption on no more than 3 interfaces
        if ethpack.eth_src_mac == self.kernel_routes[0][2] or ethpack.eth_src_mac == self.kernel_routes[1][2] or ethpack.eth_src_mac == self.kernel_routes[2][2]:
          print "[INFO]: dropping packet from us..."
          continue

        # handle IP
        if ethpack.eth_type == 0x0800:
          print "[INFO]: TYPE = IP"
          
          ippack = IPPacket()
          ippack.unpack(ethpack.payload)
          
          print " [INFO]: " + ippack.stringSrcAddr() + " -> " + ippack.stringDestAddr()
          
          # check for ICMP to see if we're getting a ping
          # just handle the packet normally and forward it otherwise
          if ippack.ip_proto == 0x01:     # ICMP
            # TODO (Dragon): check if we are the recipient
            if (ippack.ip_destination == socket.inet_aton("192.168.1.1")) or (ippack.ip_destination == socket.inet_aton("192.168.2.1")) or (ippack.ip_destination == socket.inet_aton("192.168.3.1")):
              print "[INFO]: ping was for us"
              # TODO (Dragon): make a reply. if its a ping for the iface it came in on, echo respond. if not, reply that its unreachable
          
          # check the cache first to see if its in there
          try:
            newMAC = ARPdict[ippack.ip_destination]
            print "   [INFO]: Address in cache"
          except KeyError:    # wasnt in cache, broadcast an ARP
            print "   [INFO]: Address not in cache. Bcasting..."
          
          # decrement the TTL
          ippack.ip_ttl -= 1
          if ippack.ip_ttl <= 0:  # TTL ran out, send an expired message to the sender
            print "   [INFO]: TTL expired"
            # TODO (Dragon): send expired message
            
            continue  # go wait for new packets

          # pack it all back up
          newPack = ippack.pack()   # also computes the new checksum
          
          # find longest prefix match for iface
          # this is kind of dirty but oh well
          maxP = 0
          bestRoute = ("", 0, 0)
          for route in self.kernel_routes: # routes are a tuple of (ifname, destip, ifmac)
            i = 0
            prefLen = prefixMatchSize32(int(binascii.hexlify(ippack.ip_destination), 16), route[1])
            if prefLen > maxP:
              maxP = prefLen
              bestRoute = route
            i += 1
          
          # make a new ethernet header
          newFrame = ETHPacket(dst=str(ARPdict[ippack.ip_destination]), src=str(bestRoute[2]), data=newPack)
          fPack = newFrame.pack()
          
          # send it over the appropriate iface
          sFwd = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
          print "[DBUG]: sending on " + bestRoute[0]
          sFwd.bind((bestRoute[0], 0))
          sFwd.send(fPack)
          sFwd.close()
          
        # handle ARP
        elif ethpack.eth_type == 0x0806:
          print "[INFO]: TYPE = ARP"
          arppack = ARPPacket()
          arppack.unpack(ethpack.payload)
          
          # see if its a request or reply
          if arppack.arp_oper == 1:   # request
            print " [INFO]: OPER = REQ"
            print "   [ARP]: SHA: " + arppack.stringSrcMAC()
            print "   [ARP]: SPA: " + arppack.stringSrcAddr()
            print "   [ARP]: THA: " + arppack.stringDestMAC()
            print "   [ARP]: TPA: " + arppack.stringDestAddr()
            # was it meant for us?
            if (arppack.arp_tpa == socket.inet_aton("192.168.1.1")) or (arppack.arp_tpa == socket.inet_aton("192.168.2.1")) or (arppack.arp_tpa == socket.inet_aton("192.168.3.1")):
              # create a new ARP packet and send it
              newARP = ARPPacket(oper=2, sha=ARPdict[arppack.arp_tpa], spa='', tha='', tpa='')
              newEth = ETHPacket(dst=arppack.arp_sha)

            
            #else:
            # if not, forward it
          elif arppack.arp_oper == 2: # reply, get it back to the requesting host
            print " [INFO]: OPER = REPLY"
            print "   [ARP]: SHA: " + arppack.stringSrcMAC()
            print "   [ARP]: SPA: " + arppack.stringSrcAddr()
            print "   [ARP]: THA: " + arppack.stringDestMAC()
            print "   [ARP]: TPA: " + arppack.stringDestAddr()
        
        
        
      except socket.timeout:
        continue # NOP. really just need this so we can exit on keyboardinterrupt


  
def main():
  try:
    # make our sockets
    s1 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s2 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s3 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    
    # bind em
    s1.bind(("r0-eth1", 0))
    s2.bind(("r0-eth2", 0))
    s3.bind(("r0-eth3", 0))
  
    # handle errors
  except socket.error, msg:
    print "[ERR]: couldnt make the socket: " + str(msg[0]) + " " + str(msg[1])
    sys.exit()

  # spin up a thread for each interface
  t1 = IfaceThread(s1)
  t2 = IfaceThread(s2)
  t3 = IfaceThread(s3)
  
  t1.start()
  t2.start()
  t3.start()
  
  while True:
    try:
      t1.join(1)
      t2.join(1)
      t3.join(1)
    except KeyboardInterrupt:
      print "[INFO]: KeyboardInterrupt. Bailing..."
      t1.kill = True
      t2.kill = True
      t3.kill = True
      sys.exit()
  
if __name__ == '__main__':
  main()
  