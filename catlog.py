import platform
import os

def print_banner():
    print("==========================================================")
    print("..######.....###....########.##........#######...######...")
    print(".##....##...##.##......##....##.......##.....##.##....##..")
    print(".##........##...##.....##....##.......##.....##.##........")
    print(".##.......##.....##....##....##.......##.....##.##...####.")
    print(".##.......#########....##....##.......##.....##.##....##..")
    print(".##....##.##.....##....##....##.......##.....##.##....##..")
    print("..######..##.....##....##....########..#######...######...")
    print("==========================================================")

# Function to check the approporiate operating system
def get_system_info():
    os_name = platform.system()

    if os_name == "Linux":
        print(f"Detected OS: {os_name}")
        linux_log_paths = "/var/log/auth.log"
        if os.path.exists(linux_log_paths):
            print(f"Linux log file found at: {linux_log_paths}")
        else:
            print(f"Linux log file not found at: {linux_log_paths}")
        
    # Linux logs like /var/log/auth.log
    # Add Linux-specific log retrieval code here
    elif os_name == "Windows":
        print(f"Detected OS: {os_name}")
        print(f"Windows logs will go here later...")
    else:
        print(f"Operating system not supported: {os_name}")
        print("This script currently only supports Linux and Windows.")

if __name__ == "__main__":
    print_banner()
    print("")
    get_system_info()
    print("")
    # Add any additional code or functionality here