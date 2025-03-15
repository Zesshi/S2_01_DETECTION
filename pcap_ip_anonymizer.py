from scapy.all import rdpcap, wrpcap, IP, TCP, Raw
import json
import hashlib
import re

def load_pcap(file_path):
    return rdpcap(file_path)

def anonymize_ip(ip):
    return "10." + ".".join(str(int(hashlib.md5(ip.encode()).hexdigest()[i:i+2], 16) % 256) for i in (0, 2, 4))

def anonymize_email(content):
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    return email_pattern.sub(lambda match: hashlib.md5(match.group().encode()).hexdigest()[:10] + "@masked.com", content)

def anonymize_pcap(input_file, output_file, mapping_file):
    packets = load_pcap(input_file)
    ip_mapping = {}
    
    for packet in packets:
        if IP in packet:
            original_src = packet[IP].src
            original_dst = packet[IP].dst
            
            if original_src not in ip_mapping:
                ip_mapping[original_src] = anonymize_ip(original_src)
            if original_dst not in ip_mapping:
                ip_mapping[original_dst] = anonymize_ip(original_dst)
                
            packet[IP].src = ip_mapping[original_src]
            packet[IP].dst = ip_mapping[original_dst]

            if packet.haslayer(TCP) and packet.haslayer(Raw):
                raw_data = packet[Raw].load.decode(errors='ignore')
                anonymized_data = anonymize_email(raw_data)
                packet[Raw].load = anonymized_data.encode()
                
                del packet[IP].chksum
                del packet[TCP].chksum
    
    with open(mapping_file, "w") as f:
        json.dump(ip_mapping, f)
    
    wrpcap(output_file, packets)
    print(f"[+] Anonymized PCAP saved to {output_file}, Mapping saved to {mapping_file}")

def deanonymize_pcap(input_file, output_file, mapping_file):
    with open(mapping_file, "r") as f:
        ip_mapping = json.load(f)
    reverse_mapping = {v: k for k, v in ip_mapping.items()}

    packets = load_pcap(input_file)
    
    for packet in packets:
        if IP in packet:
            anonymized_src = packet[IP].src
            anonymized_dst = packet[IP].dst

            if anonymized_src in reverse_mapping:
                packet[IP].src = reverse_mapping[anonymized_src]
            if anonymized_dst in reverse_mapping:
                packet[IP].dst = reverse_mapping[anonymized_dst]

            if packet.haslayer(TCP):
                del packet[IP].chksum
                del packet[TCP].chksum
    
    wrpcap(output_file, packets)
    print(f"[+] De-anonymized PCAP saved to {output_file}")

def main():
    print("[+] Choose an option:")
    print("1. Anonymize")
    print("2. De-anonymize")
    
    choice = input("[+] Please enter your selection: ")
    
    if choice == "1":
        input_file = input("[+] Name of the PCAP-File to be anonymized: ")
        output_file = input("[+] Name of the processed PCAP-File: ")
        mapping_file = input("[+] Name of the IP-Mapping File: ")
        anonymize_pcap(input_file, output_file, mapping_file)
    
    elif choice == "2":
        input_file = input("[+] Name of the anonymized PCAP-File: ")
        output_file = input("[+] Name of the de-anonymized PCAP-File: ")
        mapping_file = input("[+] Name of the IP-Mapping File: ")
        deanonymize_pcap(input_file, output_file, mapping_file)
    
    else:
        print("[!] Invalid selection. Shutting down the process.")

if __name__ == "__main__":
    main()
