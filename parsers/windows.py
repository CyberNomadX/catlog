import win32evtlog

def parse_event_4625(strings):
    try:
        return {
            "Username": strings[5],
            "Workstation": strings[11],
            "Source IP": strings[18],
            "Status": strings[23],
            "Sub Status": strings[26],
            "Failure Code": strings[27],
        
        }
    except IndexError:
        return {"Error": "Not enough data in event"}

def parse_event_4624(strings):
    try:
        return {
            "Username": strings[5],
            "Domain": strings[6],
            "Logon ID": strings[7],
            "Logon Type": strings[8],
            "Process Name": strings[17],
            "Source IP": strings[18],
        }
    except IndexError:
        return {"Error": "Not enough data in event"}

def parse_event_4672(strings):
    try:
        return {
            "Username": strings[1],
            "Domain": strings[2],
            "Logon ID": strings[3],
            "Privileges": strings[4],
        }
    except IndexError:
        return {"Error": "Not enough data in event"}

def analyze_windows_logs():
    print("Analyzing Windows logs...")

    include_system = input("Do you want to include system logs? (y/n): ").strip().lower() == 'y'

    try:
        max_events = int(input("How many events would you like checked? (e.g., 500): ").strip())
    except ValueError:
        print("Invalid input, defaulting to 500.")
        max_events = 500

    save_output = input("Do you want to save this as a file? (y/n): ").strip().lower() == 'y'
    filename = None
    if save_output:
        filename = input("Enter filename (e.g., log_output.txt): ").strip()
        log_file = open(filename, 'w', encoding='utf-8')
    else:
        log_file = None
    
    server = 'localhost'
    log_type = 'Security'
    hand = win32evtlog.OpenEventLog(server, log_type)
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    print(f"Total number of events in {log_type} log: {total}")
    
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    count = 0
    max_events_to_process = 10

    try:
       while count < max_events_to_process:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break

            for event in events:
                event_id = event.EventID
               
                if event_id in [4624, 4625, 4672]:
                    print(f"\n🛡 Event ID: {event_id}")
                    print(f"> Time: {event.TimeGenerated.Format()}")
                    print(f"> Source: {event.SourceName}")

                    if event_id == 4625:
                        parsed = parse_event_4625(event.StringInserts)
                        print("Failed Login Detected:")
                    elif event_id == 4624:
                        parsed = parse_event_4624(event.StringInserts)
                        print("Successful Login:")
                    elif event_id == 4672:
                        parsed = parse_event_4672(event.StringInserts)
                        username = parsed.get("Username", "").upper()

                    username = parsed.get("Username", "").upper()

                    if not include_system and username in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                        continue
                        
                        if username not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                            print("Real User Elevated Privileges Detected!")
                        else:
                            print("System-level Privileged Logon:")


                    for key, value in parsed.items():
                        print(f"   - {key}: {value}")

                    count += 1

                if count >= max_events_to_process:
                    break
    finally:              
        win32evtlog.CloseEventLog(hand)
        print(f"Finished scanning. Total relevant events found: {count}")