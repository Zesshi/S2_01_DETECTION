import sys
import re
from collections import defaultdict

def parse_auth_log(file_path, threshold):
    attempts = defaultdict(lambda: defaultdict(int))  # {IP: {date: count}}
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')  # Matches IPv4 addresses

    with open(file_path, 'r') as file:
        for line in file:
            if "Failed password" in line or "Invalid user" in line:
                parts = line.split()
                date = " ".join(parts[0:2])  # Extract month and day
                match = ip_pattern.search(line)
                if match:
                    ip = match.group()
                    attempts[ip][date] += 1

    # Filter by threshold
    results = {}
    for ip, dates in attempts.items():
        for date, count in dates.items():
            if count > threshold:
                if ip not in results:
                    results[ip] = []
                results[ip].append((date, count))
    return results

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 ssh_brute_force_detector.py <threshold> <auth_log_path>")
        sys.exit(1)

    threshold = int(sys.argv[1])
    log_path = sys.argv[2]

    results = parse_auth_log(log_path, threshold)
    for ip, data in results.items():
        print(f"IP: {ip}")
        for date, count in data:
            print(f"  Date: {date}, Attempts: {count}")
