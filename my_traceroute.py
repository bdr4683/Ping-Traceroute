import socket
import struct
import argparse
import time
import random
import os

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

def getHostname(ip, numeric):
    """
    Return the hostname or IP based on the -n flag.
    """
    if numeric:
        return ip
    else:
        return ip + " " + socket.gethostbyaddr(ip)[0]
    
def traceroute(destination, nqueries=3, numeric=False, summary=False):
    """
    OH GOD WHY DO YOU NOT WORK
    """
    MAX_HOPS = 30
    TIMEOUT = 2
    icmp_id = os.getpid() & 0xFFFF  # Unique ID in case that helps
    seq_base = 1 
    
    dest_ip = resolveHostname(destination)
    print(f"traceroute to {destination} ({dest_ip}), {MAX_HOPS} hops max, {nqueries} probes per hop")

    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(TIMEOUT)
    
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) 
    for ttl in range(1, MAX_HOPS + 1):
        udp_sock.settimeout(TIMEOUT)
        probes = {}
        
        # Sequence numbers (probably not necessary but I was told it might help)
        seq_numbers = [seq_base + (ttl-1)*nqueries + i for i in range(nqueries)]
        
        # Send probes
        for seq in seq_numbers:
            udp_sock.sendto(b'', (dest_ip, 33434 + seq))
            probes[seq] = {'sent': time.time(), 'addr': None, 'rtt': None}
        
        start_time = time.time()
        while time.time() - start_time < TIMEOUT:
            try:
                packet, addr = icmp_sock.recvfrom(512)
                
                origSeq = struct.unpack('!H', packet[54:56])[0] 
                
                if origSeq in probes:
                    rtt = (time.time() - probes[origSeq]['sent']) * 1000
                    probes[origSeq]['addr'] = addr[0]
                    probes[origSeq]['rtt'] = rtt
            except (socket.timeout, struct.error):
                break

        output = f"{ttl}  "
        unanswered = 0
        
        for seq in seq_numbers:
            if probes[seq]['addr']:
                host = getHostname(probes[seq]['addr'], numeric)
                output += f"{host} {probes[seq]['rtt']:.1f}ms  "
            else:
                output += "*  "
                unanswered += 1
        
        if summary:
            output += f" ({unanswered} unanswered)"
            #TODO: Fill in more later
        
        print(output)
        
        # Check if we reached destination
        if any(probe['addr'] == dest_ip for probe in probes.values()):
            break

def main():
    parser = argparse.ArgumentParser(description="Custom traceroute implementation.")
    parser.add_argument("destination", help="The destination address to trace.")
    parser.add_argument("-n", action="store_true", help="Print numeric addresses only.")
    parser.add_argument("-q", type=int, default=3, dest="nqueries", help="Number of probes per TTL.")
    parser.add_argument("-S", action="store_true", help="Print summary of unanswered probes.")
    args = parser.parse_args()

    try:
        traceroute(args.destination)
    except PermissionError:
        print("Error: Root privileges required for raw sockets.")
    except KeyboardInterrupt:
        print("Program terminated by keyboard interrupt")

if __name__ == "__main__":
    main()