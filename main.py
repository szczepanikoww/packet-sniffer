import socket
import struct
import textwrap

# keep looping to receive packets
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

#unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#return propelrly formatted MAC address (11:11:11:11:11:11)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# unpacking ipv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4 # reading length of header to know where data starts
    ttl, proto, src, target = struct.unpack('!8x B B 3x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:] # last one is data (payload)

#return properly formatted ipv4 address (127.0.0.1)
def ipv4(addr):
    return '.'.join(map(str, addr))
    
main()