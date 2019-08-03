import socket
import struct
import sys
import threading
import time
import binascii
import string
from ctypes import create_string_buffer

# unpack string
ARP_PACK_STR = "!HHBBH6s4s6s4s"

# ARP packet
class ARPPacket():
  
  # constructor
  def __init__(self, htype=1, ptype=0x0800, hlen=0x0006, plen=0x0004, oper=1, sha='', spa='', tha='', tpa=''):
    self.arp_htype = htype
    self.arp_ptype = ptype
    self.arp_hlen = hlen
    self.arp_plen = plen
    self.arp_oper = oper
    self.arp_sha = sha
    self.arp_spa = spa
    self.arp_tha = tha
    self.arp_tpa = tpa
  
  def pack(self):
    arpPckt = struct.pack(ARP_PACK_STR, self.arp_htype, self.arp_ptype, self.arp_hlen,
                          self.arp_plen, self.arp_oper, self.arp_sha, self.arp_spa,
                          self.arp_tha, self.arp_tpa)
    return arpPckt
    
  def unpack(self, arpPckt):
    headLength = struct.calcsize(ARP_PACK_STR)      # should always be 28
    arpHdr = arpPckt[:headLength]                   # get just the arp header from the packet
    arpTuple = struct.unpack(ARP_PACK_STR, arpHdr)
    
    self.arp_htype = arpTuple[0]
    self.arp_ptype = arpTuple[1]
    self.arp_hlen = arpTuple[2]
    self.arp_plen = arpTuple[3]
    self.arp_oper = arpTuple[4]
    self.arp_sha = arpTuple[5]
    self.arp_spa = arpTuple[6]
    self.arp_tha = arpTuple[7]
    self.arp_tpa = arpTuple[8]
    
  # turn the destination IP into a formatted string
  def stringDestAddr(self):
    return socket.inet_ntoa(self.arp_tpa)
  
  # turn the source IP into a formatted string
  def stringSrcAddr(self):
    return socket.inet_ntoa(self.arp_spa)
  
  # turn the dest mac into a formatted string
  def stringDestMAC(self):
    mac = ''.join("{:02x}".format(ord(c)) for c in self.arp_tha)
    return mac
  
  # turn the src mac into a formatted string
  def stringSrcMAC(self):
    mac = ''.join("{:02x}".format(ord(c)) for c in self.arp_sha)
    return mac
    