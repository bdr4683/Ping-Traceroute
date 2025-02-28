import socket
import struct
import time

# Checksum function, obtained from a guide online
def checksum(source):
    checksum = 0
    for i in range(0, len(source), 2):
        checksum += (source[i] << 8) + (
            struct.unpack('B', source[i + 1:i + 2])[0]
            if len(source[i + 1:i + 2]) else 0
        )

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

def createPacket(payloadSize):
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
    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Error, root privilages not found")
        return

    packet = createPacket(packetSize)

    mySocket.sendto(packet, (address, 1))   
    mySocket.settimeout(timeout)
    start = time.time()
    

def main():
    print('hello world')

if __name__ == '__main__':
    main()