import socket
import struct
import sys
import threading
import time
import binascii
import string
from ctypes import create_string_buffer

# helper functions

# return the bit width of a value
def bitLen(i):
  length = 0
  while i:
    i >>= 1
    length += 1
  return length

# quickly swap the endianness of a 32 bit int
def swap32(val):
  return (((val << 24) & 0xFF000000) |
          ((val << 8)  & 0x00FF0000) |
          ((val >> 8)  & 0x0000FF00) |
          ((val >> 24) & 0x000000FF))

# return the count of bits that match in the prefix (32 bit values only)
def prefixMatchSize32(v1, v2):
  #print "[DBUG]: prefix for " + str(v1) + " and " + str(v2)
  length = 0
  i = 1 << 31
  s1 = swap32(v1)   
  s2 = swap32(v2)
  while (v1 & i) == (v2 & i):
    i >>= 1
    length += 1
  return length

# turn a MAC address string into a set of 6 bytes
def deMACify(macStr):
  ret = string.replace(macStr, ":", "")
  return binascii.unhexlify(ret)