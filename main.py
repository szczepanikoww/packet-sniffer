import socket
import struct
import textwrap

tab = lambda num: '\t' * num + ' - '
data_tab = lambda num: '\t' * num

# keep looping to receive packets
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(tab(1) + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # checking if dealing with ipv4 (protocol == 8)
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(tab(1) + 'IPv4 Packet:')
            print(data_tab(2) + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(data_tab(2) + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1: 
                icmp_type, code, checksum, data = icmp_packet(data)
                print(tab(1) + 'ICMP Packet:')
                print(data_tab(2) + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(tab(1) + 'Data:')
                print(fromat_multi_line(data_tab(2), data))
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(tab(1) + 'TCP Segment:')
                print(data_tab(2) + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(data_tab(2) + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(data_tab(2) + 'Offset: {}, Flags: URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(tab(1) + 'Data:')
                print(fromat_multi_line(data_tab(2), data))
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print(tab(1) + 'UDP Segment:')
                print(data_tab(2) + 'Source Port: {}, Destination Port: {}, Size: {}'.format(src_port, dest_port, size))
                print(tab(1) + 'Data:')
                print(fromat_multi_line(data_tab(2), data))
            else:
                print(tab() + 'Other IPv4 Data:')
                print(fromat_multi_line(data_tab(2), data))

#unpacks ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#return propelrly formatted MAC address (11:11:11:11:11:11)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# unpacks ipv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4 # reading length of header to know where data starts
    ttl, proto, src, target = struct.unpack('!8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:] # last one is data (payload)

#return properly formatted ipv4 address (127.0.0.1)
def ipv4(addr):
    return '.'.join(map(str, addr))

# unpack icmp packet
def icmp_packet(data):
    imcp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return imcp_type, code, checksum, data[4:] #last one is data (payload)

#unpacks tcp segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14] )
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


#unpack udp segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# formats multi-line data
def fromat_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()