# Main file
import os
import platform
import subprocess
import sys
from time import sleep

import os_test

CURRENT = {
    "target": None,
    "targetType": None,
    "protocol": "TCP",
    "scanType": "connect",
    "ports": "80",
    "serviceScan": False,
    "intensity": "7",
    "OSDetection": False,
    "timing": "3"
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
    if not os_test.is_nmap_installed():
        print("    Nmap is not found!")
        return False
    print("    Nmap is found!")
    return True


# ------------------
# Functional block
# ------------------

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
            CURRENT["target"] = f"file at {file_path}"
            break
        elif choice == "3":
            CURRENT["targetType"] = "random"
            num_targets = int(input("Enter the number of random targets: "))
            CURRENT["target"] = f"{num_targets} random targets"
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
        Please select the scan type:
        [1] Connect
        [2] SYN
        [3] ACK
        [4] Window Scan
        [5] Maimon Scan
        [6] Null Scan
        [7] FIN Scan
        [8] Xmas Scan
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


def set_service_version_scan():
    print("""
    Please select the service version scan:
    [0] Maximum power (OS scan, version detection, traceroute...)
    [1] Enable
    [2] Disable
    """)
    while True:
        choice = input("Select your service version scan: ")
        if choice == "1":
            CURRENT["serviceScan"] = True
            break
        elif choice == "2":
            CURRENT["serviceScan"] = False
            break
        elif choice == "0":
            CURRENT["serviceScan"] = True
            CURRENT["intensity"] = "10"
        else:
            print("Invalid choice. Please try again.")

    if CURRENT["serviceScan"] and CURRENT["intensity"] != "10":
        while True:
            intensity = input("Enter the intensity level (1-9): ")
            if intensity.isdigit() and 1 <= int(intensity) <= 9:
                CURRENT["intensity"] = intensity
                break
            else:
                print("Invalid choice. Please try again.")

    print("""
    Do you want to enable OS detection? (Y/N)
    """)
    while True:
        choice = input("Select your OS detection: ")
        if choice.lower() == "y":
            CURRENT["OSDetection"] = True
            break
        elif choice.lower() == "n":
            CURRENT["OSDetection"] = False
            break
        else:
            print("Invalid choice. Please try again.")


def set_timing():
    print("""
    Please select the timing:
    [0] Paranoid
    [1] Sneaky
    [2] Polite
    [3] Normal
    [4] Aggressive
    [5] Insane
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
    elif selected == "t":
        set_timing()
    elif selected == "e":
        execute()
    elif selected == "q":
        print("Exiting...")
        exit(0)
    else:
        print("Invalid option. Please try again.")


def print_options():
    print(f"""
    [1] Set target (current: {CURRENT["target"]}) 
    [2] Set scan type (current: {CURRENT["protocol"]} {CURRENT["scanType"]})
    [3] Set ports (current: {CURRENT["ports"] if "ports" in CURRENT else "not set"})
    [4] Set service scanning (current: {CURRENT["serviceScan"]} with intensity {CURRENT["intensity"]} if applicable. OS detection: {CURRENT["OSDetection"]} )
    
    [T] Set timing/performance (current: {CURRENT["timing"]})
    [E] Execute scan
    [Q] Quit
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

    return PARAMS


def execute():
    params = construct_parameters()
    command = f"nmap{params}"
    print(f"Executing command: {command}")

    output = subprocess.run(command, shell=True, check=True, stdout=sys.stdout, stderr=sys.stderr)

if __name__ == "__main__":
    main()