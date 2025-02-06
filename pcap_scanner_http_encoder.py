import pyshark
import urllib.parse
import sys
import base64
import binascii

def decode_param(param):
    # base64
    try:
        decoded = base64.b64decode(param)
        if decoded.isascii():
            return decoded.decode('utf-8')
    except (binascii.Error, UnicodeDecodeError):
        pass
    
    # base32
    try:
        decoded = base64.b32decode(param)
        if decoded.isascii():
            return decoded.decode('utf-8')
    except (binascii.Error, UnicodeDecodeError):
        pass
    
    # hex
    try:
        decoded = bytes.fromhex(param)
        if decoded.isascii():
            return decoded.decode('utf-8')
    except ValueError:
        pass
    
    # binary
    try:
        decoded = bin(int(param, 2)).encode('utf-8')
        return decoded.decode('utf-8')
    except ValueError:
        pass

    return param

def extract_http_parameters(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="http.request")
    
    for pkt in cap:
        try:
            if hasattr(pkt, 'http') and hasattr(pkt.http, 'request_uri'):  
                uri = pkt.http.request_uri
                
                params = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)
                
                for key, values in params.items():
                    for value in values:
                        decoded_value = decode_param(value)
                        
                        print(f"[+] Request URI: {uri}")
                        print(f"[+] {key}: {decoded_value}")
                        print("-" * 50)
        except AttributeError:
            continue
    
    cap.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[!] Usage: python3 http_message_filter.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    extract_http_parameters(pcap_file)
