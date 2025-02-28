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

    checksum = 0
    for i in range(0, len(source), 2):
        checksum += (source[i] << 8) + (
            struct.unpack('B', source[i + 1:i + 2])[0]
            if len(source[i + 1:i + 2]) else 0
        )

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

def resolve_hostname(destination):
    """
    Resolve a hostname or IP address to an IPv4 address.
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
        count = float('inf')
        if args.count:
            count = args.count
        packet_size = args.packetsize
        wait = args.wait
        timeout = args.timeout

        while count > 0:
            ping(args.destination, timeout, packet_size)
            count -= 1
            if count > 0:
                time.sleep(wait)
    except KeyboardInterrupt:
        print("\nPing interrupted.")

if __name__ == '__main__':
    main()