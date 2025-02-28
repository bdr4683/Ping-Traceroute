import socket
import struct
import argparse
import time

def checksum(source):
    """
    Basic checksum function from online reference

    :param struct source: input packet
    :return: the checksum of the packet
    """

    s = 0
    for i in range(0, len(source) - (len(source) % 2), 2):
        s += (source[i] << 8) + source[i + 1]
    if len(source) % 2:
        s += source[-1] << 8  # Pad last byte with 0x00
    s = (s >> 16) + (s & 0xFFFF)
    s = ~s & 0xFFFF
    return s

def resolveHostname(destination):
    """
    Resolve a hostname or IP address to an IPv4 address.

    :param string destination: Target destination
    :return: IPv4 address of the destination
    """
    try:
        addr_info = socket.getaddrinfo(
            destination, 
            None, 
            socket.AF_INET, 
            socket.SOCK_RAW, 
            socket.IPPROTO_ICMP
        )
        
        ip_address = addr_info[0][4][0]
        return ip_address
    except socket.gaierror:
        raise ValueError(f"Could not resolve: {destination}")
    
def createPacket(payloadSize, seq):
    """
    Creates and returns an ICMP ping packet

    :param int payloadSize: size of the data being sent
    :return: a formatted icmp packet
    """

    icmpType = 8
    icmpCode = 0
    icmpId = 0
    icmpChecksum = 0
    icmpSeq = seq

    data = b'a' * payloadSize

    icmpHeader = struct.pack("!BBHHH", icmpType, icmpCode, icmpChecksum, icmpId, icmpSeq)

    # Calculate the actual checksum
    icmpChecksum = checksum(icmpHeader + data)

    icmpHeader = struct.pack("!BBHHH", icmpType, icmpCode, icmpChecksum, icmpId, icmpSeq)

    return icmpHeader + data

