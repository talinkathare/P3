import struct
import sys




class Packet_header:
    def __init__(self, ts_sec, ts_usec, incl_len, orig_len):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.incl_len = incl_len
        self.orig_len = orig_len

class IPV4_header:
    def __init__(self, ttl, protocol, flags, frag_offset, src_ip, dst_ip):
        self.ttl = ttl
        self.protocol = protocol
        self.flags = flags
        self.frag_offset = frag_offset
        pass

# Define structures for global header and packet header
def read_pcap(file_path):
    with open(file_path, 'rb') as f:
        # Read the global header
        global_header_data = f.read(24)
        # Read packets
        packets = {}
        while True:
            packet_number = 0
            packet_header_data = f.read(16)
            if len(packet_header_data) < 16:
                break  # End of file


            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header_data)

            packet_header = Packet_header(ts_sec, ts_usec, incl_len, orig_len)
            packet_data = f.read(packet_header.incl_len)
            


            packets[packet_number]=((packet_header, packet_data))
            ip_header = packet_data[14:34]


            packet_number += 1
            #print(f"\nPacket Header: {packet_header}")
            #print(f"Packet Data: {packet_data.hex()}")
        
        return  packets
def read_IPv4_header(packet_data):
    # Unpack the IPv4 header fields
    version_ihl = packet_data[0]
    ttl = packet_data[8]
    protocol = packet_data[9]
    flags_frag_offset = struct.unpack('!H', packet_data[6:8])[0]
    flags = (flags_frag_offset >> 13) & 0x07
    frag_offset = flags_frag_offset & 0x1FFF
    src_ip = struct.unpack('!BBBB', packet_data[12:16])
    dst_ip = struct.unpack('!BBBB', packet_data[16:20])
    
    ipv4_header = IPV4_header(ttl, protocol, flags, frag_offset, src_ip, dst_ip)
    
    print(f"IPv4 Header: {ipv4_header}")
    
    return ipv4_header

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