#!/usr/bin/env python3

from cysystemd.reader import JournalReader, JournalOpenMode
import json
import sys

def compute_failure_event(session, event, time_window, threshold):
    event_message = event['MESSAGE']
    print(event_message)

    if 'Failed password' not in event_message:
        return

    print('[+] Invalid Login detected')

    src_ip = event_message.split()[5]
    timestamp_seconds = int(event['_SOURCE_REALTIME_TIMESTAMP']) / 1000000

    if src_ip not in session:
        #Creating new session entry
        session[src_ip] = {
            'timestampSeconds' : timestamp_seconds,
            'counter' : 1
        }
    else:
        #Increase counter if there was an event within the time window
        delta = timestamp_seconds - session[src_ip]['timestampSeconds']

        if delta > time_window:
            #reset counter
            session[src_ip]['counter'] = 1
        else:
            #increase counter by 1
            session[src_ip]['counter'] += 1
            
        #update TimeStamp
        session[src_ip]['timestampSeconds'] = timestamp_seconds

        #Evaluate alarm
        if session[src_ip]['counter'] >= threshold:
            print("[!] Brute-Force attempt detected. With a maximal timewindow of " + str(time_window) + " seconds, an attacker tried at least " + str(threshold) + " times each window to log in with an invalid password.")
    
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

    session = {}
    
    while True:
        try:
            # Read and print log entries
            reader.wait(poll_timeout)
            for event in reader:
                if event['SYSLOG_IDENTIFIER'] == 'sshd-session':
                    compute_failure_event(session, event, time_window, threshold)
                
        except KeyboardInterrupt:
            print("[-] Stopping SSH Brute Force Detector.")
            break

if __name__ == "__main__":
    main()
