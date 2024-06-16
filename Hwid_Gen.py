import subprocess
import hashlib

def generate_hwid():
    # Use WMIC to get the baseboard (motherboard) serial number
    baseboard_serial = subprocess.check_output("wmic baseboard get serialnumber", shell=True).decode().split("\n")[1].strip()

    # Hash the baseboard serial number to create a unique HWID
    hwid = hashlib.md5(baseboard_serial.encode()).hexdigest()
    return hwid

def save_hwid_to_file(filename):
    hwid = generate_hwid()
    with open(filename, 'w') as file:
        file.write(hwid)

if __name__ == "__main__":
    save_hwid_to_file("hwid.txt")
    print("HWID saved to hwid.txt")
