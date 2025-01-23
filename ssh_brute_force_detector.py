import sys
import re
from datetime import datetime, timedelta
from collections import defaultdict

def parse_auth_log(file_path, threshold, time_window):
    attempts = defaultdict(list)  # {IP: [(datetime, count)]}
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')  # Matches IPv4 addresses
    date_pattern = re.compile(r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})')  # Matches timestamps

    with open(file_path, 'r') as file:
        for line in file:
            if "authentication failure" in line or "Failed password" in line:
                match_date = date_pattern.search(line)
                match_ip = ip_pattern.search(line)
                if match_date and match_ip:
                    log_time = datetime.strptime(f"{datetime.now().year} " + match_date.group(), "%Y %b %d %H:%M:%S")
                    ip = match_ip.group()
                    attempts[ip].append(log_time)

    # Filter attempts within the time_window
    results = {}
    time_delta = timedelta(seconds=time_window)
    for ip, times in attempts.items():
        times.sort()  # Sort timestamps for the IP
        count = 0
        start_time = times[0]

        for time in times:
            if time - start_time <= time_delta:
                count += 1
            else:
                # Reset counter and adjust window
                if count > threshold:
                    results[ip] = results.get(ip, 0) + count
                count = 1
                start_time = time

        # Final check for the last window
        if count > threshold:
            results[ip] = results.get(ip, 0) + count

    return results

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 ssh_brute_force_detector.py <threshold> <time_window_in_seconds> <auth_log_path>")
        sys.exit(1)

    threshold = int(sys.argv[1])
    time_window = int(sys.argv[2])
    log_path = sys.argv[3]
    
    print(f"[+] Starting Brute Force Detector.")
    print(f"Following Parameters have been set:")
    print(f"Threshold: {threshold} || Time Window: {time_window} seconds || Log Path: {log_path}")
    print(f"===================================")

    results = parse_auth_log(log_path, threshold, time_window)
    for ip, count in results.items():
        print(f"IP: {ip}, Total Attempts: {count}")
