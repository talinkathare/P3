import struct
import sys
import socket




class Packet_header:
    def __init__(self, ts_sec, ts_usec, incl_len, orig_len):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.incl_len = incl_len
        self.orig_len = orig_len

class IPV4_header:
    def __init__(self, header, protocol, flags, frag_offset, dst_ip, src_ip):
        self.header = header
        self.protocol = protocol
        self.flags = flags
        self.frag_offset = frag_offset
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        pass

# Define structures for global header and packet header
def read_pcap(file_path):
    with open(file_path, 'rb') as f:
        # Read the global header
        global_header_data = f.read(24)
        # Read packets
        packets = {}
        destination_ip_found = False
        destination_ip = None
        while True:
            packet_number = 0
            packet_header_data = f.read(16)
            if len(packet_header_data) < 16:
                break  # End of file


            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header_data)

            packet_header = Packet_header(ts_sec, ts_usec, incl_len, orig_len)
            packet_data = f.read(packet_header.incl_len)
            


            packets[packet_number]=((packet_header, packet_data))
            ip_header, protocol, flags, fragment_offset, dst_ip, src_ip = read_IPv4_header(packet_data)
            ip = IPV4_header(ip_header, protocol, flags, fragment_offset, dst_ip, src_ip)
            while destination_ip_found == False:

                if ip.protocol == 17:
                    print("UDP Packet Found")
                    destination_ip = ip.dst_ip
                    src_ip = ip.src_ip
                    #print(f"Source IP: {socket.inet_ntoa(src_ip)}")
                    #print(f"Destination IP: {socket.inet_ntoa(destination_ip)}")
                    destination_ip_found = True
            packet_number += 1
            #print(f"\nPacket Header: {packet_header}")
            #print(f"Packet Data: {packet_data.hex()}")
        
        return  packets
def read_IPv4_header(packet_data):
    # Unpack the IPv4 header fields
    version_ihl = packet_data[0]
    ip_header = packet_data[14:34]
    # Bytes 6-7 of IP header contain flags and fragment offset
    flags_offset_bytes = ip_header[6:8]

    # Convert to 16-bit integer (big-endian)
    flags_offset_value = int.from_bytes(flags_offset_bytes, byteorder='big')

    # Extract individual components:
    # Flags are the top 3 bits
    flags = (flags_offset_value >> 13) & 0x7  # Shift right 13, mask 3 bits

    # Fragment offset is the bottom 13 bits
    fragment_offset = flags_offset_value & 0x1FFF  # Mask 13 bits

    # Break down the flags further:
    reserved_bit = (flags >> 2) & 0x1      # Bit 0 (always 0)
    dont_fragment = (flags >> 1) & 0x1     # Bit 1 (DF flag)
    more_fragments = flags & 0x1           # Bit 2 (MF flag)
    protocol = ip_header[9]
    src_ip = ip_header[12:16]
    dst_ip = ip_header[16:20]

    
    #print(f"IPv4 Header: {ip_header}")
    
    return (ip_header, protocol, flags, fragment_offset, dst_ip, src_ip)

# analyzer.py


if __name__ == "__main__":

    
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        read_pcap(input_file)
    else:
        print("No file provided!")

def readfile(filename):
    connections = {}
    capture_start = None
    with open(filename, "rb") as f:
        global_header = f.read(24)
        raw_magic = global_header[0:4]
        if raw_magic == b'\xa1\xb2\xc3\xd4':
            endianness = '>'
        elif raw_magic == b'\xd4\xc3\xb2\xa1':
            endianness = '<'
        else:
            print("Unknown magic number:", raw_magic.hex())
            return