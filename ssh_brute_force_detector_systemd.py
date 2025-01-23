#!/usr/bin/env python3

from cysystemd.reader import JournalReader, JournalOpenMode
import json
import sys

def main():
    #### Argument Parsing ####
    if len(sys.argv) != 3:
        print("[-] Require exactly 2 Parameters.")
        exit()

    time_window = int(sys.argv[1])  # time window in seconds
    threshold = int(sys.argv[2])   # threshold number of authentication failures

    print("[+] Starting SSH Brute Force Detector.")

    reader = JournalReader()
    reader.open(JournalOpenMode.SYSTEM)
    reader.seek_tail()

    poll_timeout = 0.5

    while True:
        try:
            # Read and print log entries
            reader.wait(poll_timeout)
            for record in reader:
                print(json.dumps(record.data, indent=1, sort_keys=True))

        except KeyboardInterrupt:
            print("[-] Stopping SSH Brute Force Detector.")
            break

if __name__ == "__main__":
    main()
