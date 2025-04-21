"""Module, responsible for detecting OS as well as checking if nmap works."""

import os
import platform
import subprocess



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



if __name__ == '__main__':
    print(f"Is Windows: {is_windows()}")
    print(f"Is Linux: {is_linux()}")
    print(f"Is Mac: {is_mac()}")
    print(f"Is Nmap installed: {is_nmap_installed()}")
