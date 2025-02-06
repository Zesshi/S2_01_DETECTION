import argparse
import os
import pyshark
from scapy.all import wrpcap, Ether, IP, TCP, UDP

# check if a packet matches the possible protocols
def protocol_check(packet, protocol):
    # List of supported protocols & packet attribute
    protocols = {
        'http': 'HTTP',
        'udp': 'UDP',
        'tcp': 'TCP',
        'arp': 'ARP',
        'icmp': 'ICMP',
        'dns': 'DNS',
        'ssl': 'SSL',
        'ipx': 'IPX',
        'sip': 'SIP',
        'multicast': lambda packet: hasattr(packet, 'ip') and packet.ip.dst.startswith('224.')
    }

    # check if protocol is in dictionary and evaluate the condition (thanks ChatGPT)
    if protocol in protocols:
        check = protocols[protocol]
        if callable(check):
            return check(packet) # used for multicast lambda
        return check in packet
    return False

def filter_packets(pcap_file, filters):
    filtered_packets = []

    # Create a FileCapture object for the pcap file
    cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)

    for packet in cap:
        try:
            # Protocol filter
            if filters.get('protocol') and not protocol_check(packet, filters['protocol']):
                continue

            # IP filter
            if filters.get('src_ip') and hasattr(packet, 'ip') and packet.ip.src != filters['src_ip']:
                continue
            if filters.get('dst_ip') and hasattr(packet, 'ip') and packet.ip.dst != filters['dst_ip']:
                continue

            # Port filter
            if filters.get('src_port'):
                if hasattr(packet, 'tcp') and int(packet.tcp.srcport) != filters['src_port']:
                    continue
                elif hasattr(packet, 'udp') and int(packet.udp.srcport) != filters['src_port']:
                    continue
            if filters.get('dst_port'):
                if hasattr(packet, 'tcp') and int(packet.tcp.dstport) != filters['dst_port']:
                    continue
                elif hasattr(packet, 'udp') and int(packet.udp.dstport) != filters['dst_port']:
                    continue

            # Size filter
            if filters.get('min_size') and len(packet) < filters['min_size']:
                continue
            if filters.get('max_size') and len(packet) > filters['max_size']:
                continue

            # MAC filter
            if filters.get('src_mac') and hasattr(packet, 'eth') and packet.eth.src != filters['src_mac']:
                continue

            # If the packet passes all filters
            filtered_packets.append(packet)

        except AttributeError:
            continue

    return filtered_packets

def show_error_message(message):
    print(f"[!] {message}")

def save_filtered_packets(filtered_packets, output_file):
    scapy_packets = []
    for packet in filtered_packets:
        try:
            # Generating a packet from the filtered_packets with scapy (thanks ChatGPT)
            raw_data = packet.get_raw_packet()
            if raw_data:
                scapy_packet = Ether(raw_data)
                if 'IP' in packet:
                    scapy_packet = scapy_packet / IP(raw_data) # Add IP Layer if present
                if 'TCP' in packet:
                    scapy_packet = scapy_packet / TCP(raw_data) # Add TCP Layer if present
                elif 'UDP' in packet:
                    scapy_packet = scapy_packet / UDP(raw_data) # Add UDP Layer if present
                scapy_packets.append(scapy_packet)
        except Exception as e:
            show_error_message(f"[!] Error converting packet: {e}")

    if scapy_packets:
        wrpcap(output_file, scapy_packets)
        print(f"[+] Filtered packets saved to {output_file}")
    else:
        print("[!] No packets to save.")

def main():
    # Parsermenu if the -h Flag is requested
    parser = argparse.ArgumentParser(description='Filter packets from a .pcap file.')
    parser.add_argument('pcap_file', type=str, help='Path to the .pcap file')
    parser.add_argument('--protocol', type=str, choices=[
        'http', 'tcp', 'udp', 'arp', 'icmp', 'dns', 'ssl', 'ipx', 'sip', 'multicast'],
                        help='Filter by protocol (http, tcp, udp, arp, icmp, dns, ssl, ipx, sip, multicast)')
    parser.add_argument('--src-ip', type=str, help='Filter by source IP address')
    parser.add_argument('--dst-ip', type=str, help='Filter by destination IP address')
    parser.add_argument('--src-port', type=int, help='Filter by source port')
    parser.add_argument('--dst-port', type=int, help='Filter by destination port')
    parser.add_argument('--min-size', type=int, help='Filter packets larger than the specified size (bytes)')
    parser.add_argument('--max-size', type=int, help='Filter packets smaller than the specified size (bytes)')
    parser.add_argument('--src-mac', type=str, help='Filter by source MAC address')
    parser.add_argument('--output', type=str, default='filtered_output.pcap', help='Output file for filtered packets')

    args = parser.parse_args()

    # Check if python can see the .pcap file
    if not os.path.isfile(args.pcap_file):
        show_error_message("[!] The specified .pcap file does not exist.")
        return

    # Args-Filter for CMD-Line
    filters = {
        'protocol': args.protocol,
        'src_ip': args.src_ip,
        'dst_ip': args.dst_ip,
        'src_port': args.src_port,
        'dst_port': args.dst_port,
        'min_size': args.min_size,
        'max_size': args.max_size,
        'src_mac': args.src_mac
    }

    if not any(filters.values()):
        show_error_message("[!] Please provide at least one filter (e.g., --protocol, --src-ip, etc.).")
        return

    # Loggingmenu
    print(f"[+] Scraping {args.pcap_file} with the following filters:")
    for filter_name, filter_value in filters.items():
        if filter_value is not None:
            print(f"[+] {filter_name.replace('_', '-').capitalize()}: {filter_value}")

    # Where the magic happens
    filtered_packets = filter_packets(args.pcap_file, filters)

    # Show Exitinfo
    if filtered_packets:
        print(f"[+] Filtered packets count: {len(filtered_packets)}")
        save_filtered_packets(filtered_packets, args.output)
    else:
        print("[!] No packets matched the filter criteria.")

# Main method
if __name__ == '__main__':
    main()
