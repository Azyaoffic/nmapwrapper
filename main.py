# Main file
import platform

import os_test

def greeting():
    print(f"""
    Welcome to Nmap!
    Your platform: {platform.platform()}.
    """)

def check_nmap():
    if not os_test.is_nmap_installed():
        print("    Nmap is not found!")
        return False
    else:
        print("    Nmap is found!")
        return True


def main():
    greeting()
    chk_nmap = check_nmap()
    if not chk_nmap:
        exit(-1)


if __name__ == "__main__":
    main()