# Main file
import platform
import os_test

def greeting():
    print(f"""
    Welcome to Nmap!
    Your platform: {platform.platform()}.
    """)

    if not os_test.is_nmap_installed():
        print("    Nmap is not found. Please install Nmap and try again.")
    else:
        print("    Nmap is found.")


def main():
    greeting()


if __name__ == "__main__":
    main()