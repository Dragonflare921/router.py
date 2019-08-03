import socket
import struct
import sys
import threading
import time
import binascii
import string
from ctypes import create_string_buffer

# unpack string
IP_PACK_STR = "!BBHHHBBH4s4s"

# IPv4 packet
class IPPacket():
  
  # constructor
  def __init__(self, src_ip='', dest_ip='', ident='', 
                ver=4, ihl=5, dscp=0, flags=0,
                frag_offset=0, ttl=255, proto=1,
                options=None, data=''):
    
    self.ip_version = ver                       # IP version, always 4 here
    self.ip_ihl = ihl                           # header length in word (32 bit) count
    self.ip_dscp = dscp                         # DSCP stuff, likely unused here
    self.ip_id = ident                          # packet ID
    self.ip_flags = flags                       # packet flags
    self.ip_frag_offset = frag_offset           # fragment offset
    self.ip_ttl = ttl                           # packet TTL
    self.ip_proto = proto                       # protocol, default to ICMP
    self.ip_checksum = 0                        # keep this 0 to calc at pack time
    self.ip_source = src_ip                     # source address
    self.ip_destination = dest_ip               # destination address
    self.ip_options = options                   # mostly unused
    self.payload = data                         # rest of the packet data
    self.ip_total_length = 4 * self.ip_ihl + len(self.payload)  # calculate the total length field
  
  # take a packed struct string and calculate a new checksum for it
  def checksum(self, packedStr):
    cSum = 0
    sumTup = struct.unpack("!10H", packedStr)
    cSum = sum(sumTup)
    cSum += (cSum >> 16)
    cSum = ~cSum & 0xFFFF
    print "[DBUG]: calcd checksum: " + str(cSum)
    return cSum
  
  # pack the values into a struct
  def pack(self):
    verIHL = (self.ip_version << 4) & self.ip_ihl           # version and IHL share a byte
    flagFRAG = (self.ip_flags << 13) & self.ip_frag_offset  # flags and fragment offset share a short
    ipHdr = create_string_buffer(struct.calcsize(IP_PACK_STR))
    
    # pack the initial packet without the new checksum (using 0)
    struct.pack_into(IP_PACK_STR, ipHdr, 0, verIHL, self.ip_dscp, self.ip_total_length, self.ip_id,
                        flagFRAG, self.ip_ttl, self.ip_proto, 0, self.ip_source, self.ip_destination)
    
    self.ip_checksum = self.checksum(ipHdr.raw)    # calculate a new checksum
    struct.pack_into("!H", ipHdr, struct.calcsize(IP_PACK_STR[:8]), self.ip_checksum)  # pack the new checksum where it belongs
    ipPckt = ''.join([ipHdr.raw, self.payload]) # tack on the payload
    return ipPckt
    
    
  # unpack a struct into its component values
  def unpack(self, ipPckt):
    headLength = struct.calcsize(IP_PACK_STR)      # should always be 20
    ipHdr = ipPckt[:headLength]                    # get just the ip header from the packet
    ipTuple = struct.unpack(IP_PACK_STR, ipHdr)    # split into tuple
    
    #ipHdr2 = create_string_buffer(struct.calcsize(IP_PACK_STR))
    #struct.pack_into("!20s", ipHdr2, 0, ipHdr)
    #struct.pack_into("!H", ipHdr2, struct.calcsize(IP_PACK_STR[:8]), 0)
    #print "[DBUG]: calcd checksum: " + str(self.checksum(ipHdr2.raw))
    
    verIHL = ipTuple[0]
    flagFRAG = ipTuple[4]
    
    self.ip_version = verIHL >> 4
    self.ip_ihl = verIHL - (self.ip_version << 4)
    self.ip_dscp = ipTuple[1]
    self.ip_total_length = ipTuple[2]
    self.ip_id = ipTuple[3]
    self.ip_flags = flagFRAG >> 13
    self.ip_frag_offset = flagFRAG - (self.ip_flags << 13)
    self.ip_ttl = ipTuple[5]
    self.ip_proto = ipTuple[6]
    self.ip_checksum = ipTuple[7]
    print "[DBUG]: recvd checksum: " + str(self.ip_checksum)
    self.ip_source = ipTuple[8]
    self.ip_destination = ipTuple[9]
    self.payload = ipPckt[headLength:]
  
  # turn the destination IP into a formatted string
  def stringDestAddr(self):
    return socket.inet_ntoa(self.ip_destination)
  
  # turn the source IP into a formatted string
  def stringSrcAddr(self):
    return socket.inet_ntoa(self.ip_source)