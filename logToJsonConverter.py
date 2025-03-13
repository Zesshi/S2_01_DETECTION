import json
import sqlite3
import re
from datetime import datetime

LOG_FILE = "access.log"
DB_FILE = "data.db"
OUTPUT_FILE = "output.json"

LOG_PATTERN = re.compile(r"(\S+) -- (\S+) - - \[(.*?)\] \"(\S+) (\S+) \S+\" (\d+) (\d+)")

def parse_log_line(line):
    match = LOG_PATTERN.match(line)
    if match:
        session_id, remote_addr, timestamp_str, http_method, http_uri, http_status, response_size = match.groups()
        timestamp = int(datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S").timestamp())
        return {
            "session_id": session_id,
            "remote_addr": remote_addr,
            "timestamp": timestamp,
            "http_method": http_method,
            "http_uri": http_uri,
            "http_status": int(http_status),
            "http_response_size": int(response_size)
        }
    return None

def get_user_from_db(session_id):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM user_sessions WHERE id = ?", (session_id,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else "unknown"
    except Exception as e:
        print(f"[!] Database error: {e}")
        return "unknown"

def process_log():
    try:
        with open(LOG_FILE, "r") as file, open(OUTPUT_FILE, "w") as output_file:
            count = 0 
            for line in file:
                print(f"[+] Processing line: {line.strip()}")
                log_entry = parse_log_line(line)
                if log_entry:
                    log_entry["user"] = get_user_from_db(log_entry["session_id"])
                    json_entry = json.dumps(log_entry)
                    print(f"[+] Writing JSON: {json_entry}")
                    output_file.write(json_entry + "\n")
                    output_file.flush()
                    count += 1
            print(f"[+] Processing complete. {count} entries written to {OUTPUT_FILE}")
    except Exception as e:
        print(f"[!] Error processing log: {e}")

if __name__ == "__main__":
    process_log()
