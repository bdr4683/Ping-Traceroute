#
#   Basic ping implementation
#
#   Author: Brandon Ranallo, bdr4683
#
import socket
import struct
import time
import argparse

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
    

def createPacket(payloadSize):
    """
    Creates and returns an ICMP ping packet

    :param int payloadSize: size of the data being sent
    :return: a formatted icmp packet
    """

    icmpType = 8
    icmpCode = 0
    icmpId = 0
    icmpSeq = 1
    icmpChecksum = 0

    data = b'a' * payloadSize

    icmpHeader = struct.pack("!BBHHH", icmpType, icmpCode, icmpChecksum, icmpId, icmpSeq)

    # Calculate the actual checksum
    icmpChecksum = checksum(icmpHeader + data)

    icmpHeader = struct.pack("!BBHHH", icmpType, icmpCode, icmpChecksum, icmpId, icmpSeq)

    return icmpHeader + data

def ping(address, packetSize, timeout):
    """
    Pings the provided address with a packet of the specified size, or timeout for the ping request

    :param string address: address to send ping to
    :param int packetSize: size of the dummy packet to send
    :param int timeout: timeout limit of the socket in seconds
    :return: delay of ping
    """

    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Error, root privilages not found")
        return

    packet = createPacket(packetSize)

    mySocket.sendto(packet, (address, 1))
    if(timeout > 0):
        mySocket.settimeout(timeout)
    start = time.time()
    
    try:
        packetRecieved, recieveAddress = mySocket.recvfrom(1024)
        end = time.time()
        delay = end-start
    except socket.timeout:
        print("Ping request timed out.")
    
    mySocket.close()

    recvHeader = packetRecieved[20:28]

    return delay


def main():
    parser = argparse.ArgumentParser(description="Custom ping implementation.")
    parser.add_argument("destination", help="The destination address to ping.")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to send.")
    parser.add_argument("-i", "--wait", type=float, default=1, help="Wait time between packets.")
    parser.add_argument("-s", "--packetsize", type=int, default=56, help="Packet size.")
    parser.add_argument("-t", "--timeout", type=float, default=-1, help="Timeout in seconds.")

    args = parser.parse_args()

    try:
        destination = resolveHostname(args.destination)
        count = float('inf')
        if args.count:
            count = args.count
        packetSize = args.packetsize
        wait = args.wait
        timeout = args.timeout

        while count > 0:
            ping(address=destination, packetSize=packetSize, timeout=timeout)
            count -= 1
            if count > 0:
                time.sleep(wait)
    except KeyboardInterrupt:
        print("\nPing interrupted.")

if __name__ == '__main__':
    main()