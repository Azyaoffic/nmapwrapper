# Main file
import os
import platform
from time import sleep

import os_test

CURRENT = {
    "target": None,
    "targetType": None
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


def parse_options(selected):
    if selected == "1":
        set_target()
    elif selected == "2":
        pass
    elif selected == "3":
        pass
    else:
        print("Invalid option. Please try again.")


def print_options():
    print(f"""
    [1] Set target (current: {CURRENT["target"]}) 
    
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


if __name__ == "__main__":
    main()