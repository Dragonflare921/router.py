import socket
import struct
import sys
import threading
import time
import binascii
import string
from ctypes import create_string_buffer

# unpack string
ETH_PACK_STR = "!6s6sH"

# ethernet frame
class ETHPacket():
  
  # constructor
  def __init__(self, dst='', src='', typ=0x0800, data=''):
    self.eth_dest_mac = dst
    self.eth_src_mac = src
    self.eth_type = typ
    self.payload = data
  
  
  # pack the values up into a struct
  def pack(self):
    ethHdr = struct.pack(ETH_PACK_STR, self.eth_dest_mac, self.eth_src_mac, self.eth_type)    # pack header data
    ethFrame = ''.join([ethHdr, self.payload])                                                # tack on remaining payload
    return ethFrame
  
  
  # unpack a struct into its component values
  def unpack(self, ethFrame):
    headLength = struct.calcsize(ETH_PACK_STR)      # should always be 14
    ethHdr = ethFrame[:headLength]                  # get just the eth header from the packet
    ethTuple = struct.unpack(ETH_PACK_STR, ethHdr)  # split into tuple
    
    self.eth_dest_mac = ethTuple[0]                 # destination mac
    self.eth_src_mac = ethTuple[1]                  # source mac
    self.eth_type = ethTuple[2]                     # ethernet type
    self.payload = ethFrame[headLength:]            # shove the rest in playload
  
  
  # turn the dest mac into a pretty string
  def stringDestMAC(self):
    mac = ''.join("{:02x}".format(ord(c)) for c in self.eth_dest_mac)
    return mac
  
  
  # turn the src mac into a pretty string
  def stringSrcMAC(self):
    mac = ':'.join("{:02x}".format(ord(c)) for c in self.eth_src_mac)
    return mac