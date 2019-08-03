<span>Router.py</span>
=========

Simple IPv4 router implementation in python 2.7  
Intended for use with the mininet virtual network

## IMPORTANT NOTE:
  This project was written to spec for an assignment, and as such requires a specific configuration for mininet which is not included as part of this repository.  
  There are also some bugs preventing the 1.0 version from performing as expected, as noted at the end of this README.

  Future versions will be fixed to work independently and a configuration script will be provided.

## Contents:
  - <u><span>README.md</span></u>: This file
  - <u><span>router.py</span></u>: Main file. Run this to run the router
  - <u><span>eth.py</span></u>: Holds ethernet frame wrapper class used for easier representation of data
  - <u><span>ip.py</span></u>: Holds IP packet wrapper class used for easier representation of data
  - <u><span>arp.py</span></u>: Holds ARP packet wrapper class used for easier representation of data
  - <u><span>util.py</span></u>: Holds helper functions for utility


## Packet reception:
  Packets are recieved by a thread which is dedicated to listening to one interface. The packet is "unpacked" into a wrapper class which eases the manipulation of header fields.
 
## Packet forwarding:
  Packet forwarding works by decrementing the TTL and recalculating a checksum for the IP header. The interface on which the packet is forwarded is found via a longest prefix match. This longest prefix match is performed against the routing table file at /proc/net/route. A new ethernet header is constructed based on the hardware addresses.

## ARP cache:
  The ARP cache is implemented using a dictionary which is indexed on the IP. The ARP cache was intended to be dynamic but was unfinished and replaced with a static cache. Some logic is built for TTL expiration but there is no TTL value on the entries. The intended structure was going to be a dictionary of tuples which contained the MAC as well as the TTL. Expiration of the TTL would be managed by its own thread which decrements the TTL on each entry every second. When the TTL has reached 0, it is removed from the cache.
  
## Usage:
  To run the router software, scp the files over to the virtual machine for use.  
  Set up the mininet environment using <span>createNet.py</span>.  
  Open a terminal on the host r0, and run <span>router.py</span>.  
  To exit, send a keyboard interrupt to kill the threads gracefully.  
  
## BUGS:
  While logic is built for forwarding, checksum calculation is correct, address lookup performs correctly, longest prefix matching works as intended, and the correct values are packed and unpacked in the wrappers, I am unable to get any response from another host when pinging, even though the packet is sent over the matched interface.