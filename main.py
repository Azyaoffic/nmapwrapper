# Main file
import os
import platform
import subprocess
import sys
from time import sleep

# OS tests as well as nmap check
def is_windows() -> bool:
    """Check if the OS is Windows."""
    return platform.system() == 'Windows'


def is_linux() -> bool:
    """Check if the OS is Linux."""
    return platform.system() == 'Linux'


def is_mac() -> bool:
    """Check if the OS is Mac."""
    return platform.system() == 'Darwin'


def is_nmap_installed() -> bool:
    """Check if nmap is installed."""
    command = 'nmap -v'
    try:
        # Use subprocess to run the command and check for output
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Check if nmap is installed by checking the return code
        return result.returncode == 0
    except Exception as e:
        print(f"Error checking nmap installation: {e}")
    return False

LAST_PARAMS = []

CURRENT = {
    "target": "localhost",
    "targetType": "ip",
    "protocol": "TCP",
    "scanType": "connect",
    "ports": "1-1000",
    "topports": False,
    "serviceScan": False,
    "intensity": "7",
    "OSDetection": False,
    "timing": "3",
    "additional_params": "",
    "output_option": "stdout",
    "output_file": None,
}


# ------------------
# Printouts
# ------------------

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def greeting():
    print(f"""
    Welcome to Nmap!
    Your platform: {platform.platform()}.
    """)

def check_nmap():
    if not is_nmap_installed():
        print("    Nmap is not found!")
        return False
    print("    Nmap is found!")
    return True


# ------------------
# Functional block
# ------------------

def set_additional_params():
    CURRENT["additional_params"] = input("Enter additional parameters (ex: -Pn -sV): ")


def set_target():
    print("""
    Please select the type of target:
    [1] IP address (ex: 192.168.1.1), Range (ex: 192.168.1.1 192.168.2.1),
        Domain (ex: scanme.nmap.org), Subnetwork (ex: 192.168.1.0/24)
    [2] Targets from a file (ex: path/to/targets.txt)
    [3] Random targets
    """)

    while True:
        choice = input("Select your target type: ")
        if choice == "1":
            CURRENT["targetType"] = "ip"
            ip = input("Enter your target: ")
            CURRENT["target"] = ip
            break
        elif choice == "2":
            CURRENT["targetType"] = "file"
            file_path = input("Enter the path to the file: ")
            CURRENT["target"] = f"{file_path}"
            break
        elif choice == "3":
            CURRENT["targetType"] = "random"
            num_targets = int(input("Enter the number of random targets: "))
            CURRENT["target"] = f"{num_targets}"
            break
        else:
            print("Invalid choice. Please try again.")


def set_scan_type():
    print("""
    Please select the protocol:
    [1] TCP
    [2] UDP
    """)
    while True:
        choice = input("Select your protocol: ")
        if choice == "1":
            CURRENT["protocol"] = "TCP"
            break
        elif choice == "2":
            CURRENT["protocol"] = "UDP"
            break
        else:
            print("Invalid choice. Please try again.")

    if CURRENT["protocol"] == "UDP":
        CURRENT["scanType"] = "UDP"
    elif CURRENT["protocol"] == "TCP":
        print("""
        Please select the TCP scan type:
        [1] Connect Scan: Basic and reliable, but easily detectable by firewalls.
        [2] SYN Scan: Stealthier, doesn't complete the TCP handshake (requires root privileges).
        [3] ACK Scan: Maps firewall rules, helps determine if ports are filtered.
        [4] Window Scan: Similar to ACK, can sometimes identify open ports.
        [5] Maimon Scan: A variant of FIN scan, may bypass some firewalls.
        [6] Null Scan: No flags set, can evade some security measures.
        [7] FIN Scan: Only FIN flag set, useful for identifying open ports on Unix systems.
        [8] Xmas Scan: FIN, PSH, and URG flags set, helps identify open and closed ports.
        """)
        while True:
            choice = input("Select your scan type: ")
            match choice:
                case "1":
                    CURRENT["scanType"] = "connect"
                    break
                case "2":
                    CURRENT["scanType"] = "SYN"
                    break
                case "3":
                    CURRENT["scanType"] = "ACK"
                    break
                case "4":
                    CURRENT["scanType"] = "Window"
                    break
                case "5":
                    CURRENT["scanType"] = "Maimon"
                    break
                case "6":
                    CURRENT["scanType"] = "Null"
                    break
                case "7":
                    CURRENT["scanType"] = "FIN"
                    break
                case "8":
                    CURRENT["scanType"] = "Xmas"
                    break
                case _:
                    print("Invalid choice. Please try again.")


def set_ports():
    print("""
    Please select the ports:
    [1] Specific ports or range (ex: 22,https,1-1000)
    [2] All ports
    """)
    while True:
        choice = input("Select your ports: ")
        if choice == "1":
            ports = input("Enter the specific ports: ")
            CURRENT["ports"] = f"{ports}"
            break
        elif choice == "2":
            CURRENT["ports"] = "All ports"
            break
        else:
            print("Invalid choice. Please try again.")

    while True:
        topports = input("""
Do you want to use N top ports instead? (Y/N)
        """)

        if topports.lower() == "y":
            CURRENT["topports"] = True
            break
        elif topports.lower() == "n":
            CURRENT["topports"] = False
            break


def set_service_version_scan():
    print("""
    Please select the scanning depth:
    [1] Port scanning only (no version detection)
    [2] Version detection on open ports
    [3] Version detection with OS detection
    [4] Comprehensive scan (version detection, OS detection, traceroute, and default scripts)
    """)
    while True:
        choice = input("Select your service version scan: ")
        if choice == "1":
            CURRENT["serviceScan"] = False
            break
        elif choice == "2":
            CURRENT["serviceScan"] = True
            CURRENT["intensity"] = "7"
            break
        elif choice == "3":
            CURRENT["serviceScan"] = True
            CURRENT["intensity"] = "7"
            CURRENT["OSDetection"] = True
            break
        elif choice == "4":
            CURRENT["serviceScan"] = True
            CURRENT["intensity"] = "10"
            CURRENT["OSDetection"] = True
            CURRENT["additional_params"] += " -sC"
            break

    if CURRENT["serviceScan"] and CURRENT["intensity"] != "10":
        while True:
            intensity = input("""
Input intensity for version detection:
Enter a number from 1 (light, quick but less accurate) to 9 (aggressive, thorough but slower):
            """)
            if intensity.isdigit() and 1 <= int(intensity) <= 9:
                CURRENT["intensity"] = intensity
                break
            else:
                print("Invalid choice. Please try again.")


def set_timing():
    print("""
    Please select the timing template:
    [0] Paranoid: Extremely slow, minimizes detection (best for stealth).
    [1] Sneaky: Slower, reduces the chance of detection.
    [2] Polite: Slower than normal, reduces network load.
    [3] Normal: Default timing, suitable for most scans.
    [4] Aggressive: Faster, increases network load.
    [5] Insane: Very fast, may overwhelm the network or miss hosts.
    """)
    while True:
        choice = input("Select your timing: ")
        if choice == "0":
            CURRENT["timing"] = "0"
            break
        elif choice == "1":
            CURRENT["timing"] = "1"
            break
        elif choice == "2":
            CURRENT["timing"] = "2"
            break
        elif choice == "3":
            CURRENT["timing"] = "3"
            break
        elif choice == "4":
            CURRENT["timing"] = "4"
            break
        elif choice == "5":
            CURRENT["timing"] = "5"
            break
        else:
            print("Invalid choice. Please try again.")


def set_output_option():
    print("""
    Please select the output option:
    [1] Standard (console) output
    [2] Save to file (Text)
    [3] Save to file (XML)
    [4] Save to file (Grepable)
    """)
    while True:
        choice = input("Select your output option: ")
        if choice == "1":
            CURRENT["output_option"] = "stdout"
            CURRENT["output_file"] = None
            break
        elif choice == "2":
            file_path = input("Enter the path to the output file: ")
            CURRENT["output_option"] = "filetext"
            CURRENT["output_file"] = file_path
            break
        elif choice == "3":
            file_path = input("Enter the path to the output file: ")
            CURRENT["output_option"] = "filexml"
            CURRENT["output_file"] = file_path
            break
        elif choice == "4":
            file_path = input("Enter the path to the output file: ")
            CURRENT["output_option"] = "filegrepable"
            CURRENT["output_file"] = file_path
            break
        else:
            print("Invalid choice. Please try again.")

def set_profile():
    print("""
    Please select a scan profile:
    [1] Quick scan (100 top ports, TCP SYN, service detection)
    [2] Full scan (all ports, TCP SYN, service detection)
    [3] Stealth scan (1000 top ports, TCP SYN, no service detection)
    [4] Vulnerability scan (--script vuln)
    """)

    while True:
        choice = input("Select your scan profile: ")
        if choice == "1":
            CURRENT["profile"] = "TCP"
            CURRENT["scanType"] = "SYN"
            CURRENT["ports"] = "1-100"
            CURRENT["topports"] = True
            CURRENT["serviceScan"] = True
            break
        elif choice == "2":
            CURRENT["profile"] = "TCP"
            CURRENT["scanType"] = "SYN"
            CURRENT["ports"] = "1-65535"
            CURRENT["serviceScan"] = True
            break
        elif choice == "3":
            CURRENT["profile"] = "TCP"
            CURRENT["scanType"] = "SYN"
            CURRENT["ports"] = "1-1000"
            CURRENT["topports"] = True
            CURRENT["serviceScan"] = False
            break
        elif choice == "4":
            CURRENT["additional_params"] += " --script vuln"
            break
        else:
            print("Invalid choice. Please try again.")



# ------------------
# Input block
# ------------------


def parse_options(selected):
    selected = selected.lower()
    if selected == "1":
        set_target()
    elif selected == "2":
        set_scan_type()
    elif selected == "3":
        set_ports()
    elif selected == "4":
        set_service_version_scan()

    elif selected == "p":
        set_profile()


    elif selected == "o":
        set_output_option()
    elif selected == "a":
        set_additional_params()
    elif selected == "t":
        set_timing()
    elif selected == "e":
        execute()
    elif selected == "q":
        print("Exiting...")
        exit(0)
    elif selected == "l":
        execute_last()
    else:
        print("Invalid option. Please try again.")


def print_options():
    print(f"""
    [1] Set target (current: {CURRENT["target"]} {CURRENT["targetType"]}) 
    [2] Set scan type (current: {CURRENT["protocol"]} {CURRENT["scanType"]})
    [3] Set ports (current: {CURRENT["ports"] if "ports" in CURRENT else "not set"}. Using top ports: {CURRENT["topports"]} )
    [4] Set service scanning (current: {CURRENT["serviceScan"]} with intensity {CURRENT["intensity"]} if applicable. OS detection: {CURRENT["OSDetection"]} )
    
    [P] Select a scan profile
    
    
    [O] Set output option (current: {CURRENT["output_option"]} with file {CURRENT["output_file"]} if applicable)
    [T] Set timing/performance (current: {CURRENT["timing"]})

    [A] Set additional parameters (current: {CURRENT["additional_params"]})
    [E] Execute scan
    [Q] Quit
    
    [L] Use last used parameters
    """)

def main():
    greeting()

    chk_nmap = check_nmap()
    if not chk_nmap:
        exit(-1)

    sleep(2)

    # Main loop
    while True:
        clear_screen()
        print_options()
        select = input("\n    Select option: ")
        parse_options(select)


# ------------------
# Constructor block
# ------------------


def construct_parameters():
    PARAMS = ""

    # Target
    match CURRENT["targetType"]:
        case "ip":
            PARAMS += f" {CURRENT['target']}"
        case "file":
            PARAMS += f" -iL {CURRENT['target']}"
        case "random":
            PARAMS += f" -iR {CURRENT['target']}"

    # Scan type
    match CURRENT["scanType"]:
        case "connect":
            PARAMS += f" -sT"
        case "SYN":
            PARAMS += f" -sS"
        case "ACK":
            PARAMS += f" -sA"
        case "Window":
            PARAMS += f" -sW"
        case "Maimon":
            PARAMS += f" -sM"
        case "Null":
            PARAMS += f" -sN"
        case "FIN":
            PARAMS += f" -sF"
        case "Xmas":
            PARAMS += f" -sX"
        case "UDP":
            PARAMS += f" -sU"

    # Ports
    if CURRENT["ports"] is not None:
        if CURRENT["ports"] == "All ports":
            PARAMS += f" -p-"
        else:
            PARAMS += f" -p {CURRENT['ports']}"
    else:
        print("    No ports were specified, scanning all ports.")
        PARAMS += f" -p-"

    # Service version scan
    if CURRENT["serviceScan"]:
        if CURRENT["intensity"] == "10":
            PARAMS += f" -A"
        else:
            PARAMS += f" -sV --version-intensity {CURRENT['intensity']}"

    # OS detection
    if CURRENT["OSDetection"]:
        PARAMS += f" -O"

    # Timing
    if CURRENT["timing"] is not None:
        PARAMS += f" -T{CURRENT['timing']}"



    # Output option
    if CURRENT["output_option"] == "stdout":
        pass
    elif CURRENT["output_option"] == "filetext":
        if CURRENT["output_file"] is not None:
            PARAMS += f" -oN {CURRENT['output_file']}"
        else:
            print("    No output file was specified, using default.")
            PARAMS += f" -oN nmap_output.txt"
    elif CURRENT["output_option"] == "filexml":
        if CURRENT["output_file"] is not None:
            PARAMS += f" -oX {CURRENT['output_file']}"
        else:
            print("    No output file was specified, using default.")
            PARAMS += f" -oX nmap_output.xml"
    elif CURRENT["output_option"] == "filegrepable":
        if CURRENT["output_file"] is not None:
            PARAMS += f" -oG {CURRENT['output_file']}"
        else:
            print("    No output file was specified, using default.")
            PARAMS += f" -oG nmap_output.gnmap"


    # Additional parameters
    if CURRENT["additional_params"] != "":
        PARAMS += f" {CURRENT['additional_params']}"

    return PARAMS


def execute():
    params = construct_parameters()
    command = f"nmap{params} -v"
    print(f"Executing command: {command}")

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in process.stdout:
        print(line.decode().strip())
    process.wait()
    returncode = process.returncode

    if returncode == 0:
        print("Scan completed successfully.")
        LAST_PARAMS.clear()
        LAST_PARAMS.append([params])

    input("Press Enter to continue...")

def execute_last():
    if not LAST_PARAMS:
        print("No last parameters found.")
        input("Press Enter to continue...")
        return

    params = LAST_PARAMS[0]
    command = f"nmap{params}"
    print(f"Executing command: {command}")

    output = subprocess.run(command, shell=True, check=True, stdout=sys.stdout, stderr=sys.stderr)
    if output.returncode == 0:
        print("Scan completed successfully.")
        LAST_PARAMS.clear()
        LAST_PARAMS.append([params])

    input("Press Enter to continue...")


if __name__ == "__main__":
    main()