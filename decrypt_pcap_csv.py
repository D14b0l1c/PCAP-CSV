import subprocess
import pandas as pd
import os
import zipfile

# WPA credentials (update these)
WPA_PASSWORD = "YourPassword"
WPA_SSID = "YourSSID"

# Function to convert hexadecimal SSID to ASCII
def hex_to_ascii(hex_str):
    try:
        ascii_str = bytes.fromhex(hex_str).decode('utf-8')
        return ascii_str
    except Exception as e:
        return str(e)

# Function to execute tshark command and convert pcap to csv
def convert_pcap_to_csv(pcap_file):
    # Build WPA decryption config
    wpa_option = f'uat:80211_keys:\\"wpa-pwd\\",\\"{WPA_PASSWORD}:{WPA_SSID}\\"'

    # Define tshark command
    tshark_command = [
        "tshark",
        "-n",  # Disable name resolution for IPs and ports
        "-r", pcap_file,  # Input file
        "-o", wpa_option,  # WPA key for decrypting packets
        "-T", "fields",  # Output selected fields only

        # === Frame/Metadata ===
        "-e", "frame.number",  # Frame number
        "-e", "frame.time_epoch",  # Time in UNIX epoch format

        # === Wireless Signal Info ===
        "-e", "wlan_radio.signal_db",  # Signal strength (dBm)
        "-e", "wlan_radio.channel",  # Channel number

        # === SSID and Protocol ===
        "-e", "wlan.ssid",  # SSID (may be hex)
        "-e", "_ws.col.Protocol",  # Protocol type

        # === IP/Network Layer ===
        "-e", "ip.ttl",  # IP Time To Live

        # === MAC Addresses ===
        "-e", "wlan.bssid",  # BSSID (AP MAC)
        "-e", "wlan.sa",  # Source address
        "-e", "wlan.ta",  # Transmitter address
        "-e", "wlan.ra",  # Receiver address
        "-e", "wlan.da",  # Destination address

        # === IP Addresses ===
        "-e", "ip.src",  # Source IP
        "-e", "ip.dst",  # Destination IP

        # === TCP Ports and Flags ===
        "-e", "tcp.srcport",  # TCP source port
        "-e", "tcp.dstport",  # TCP destination port
        "-e", "tcp.flags",  # TCP control flags

        # === Frame Summary ===
        "-e", "_ws.col.Info",  # Info column
        "-e", "frame.len",  # Frame size in bytes
        "-e", "frame.time_delta_displayed",  # Delta from previous displayed frame

        # === GPS Info (if present) ===
        "-e", "ppi_gps.lat",  # Latitude
        "-e", "ppi_gps.lon",  # Longitude
        "-e", "ppi_gps.alt",  # Altitude

        # === Output Format ===
        "-E", "header=y",  # Include column headers
        "-E", "separator=,"  # Use comma as delimiter
    ]

    # Run tshark
    process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if error:
        print(f"Error occurred while executing tshark on {pcap_file}: {error.decode()}")
        return False

    # Parse output
    output_lines = output.decode().split('\n')
    if not output_lines or not output_lines[0].strip():
        print(f"No data extracted from {pcap_file}")
        return False

    header = output_lines[0].split('|')
    data = [line.split('|') for line in output_lines[1:] if line.strip()]
    df = pd.DataFrame(data, columns=header)

    # Convert hex SSIDs to ASCII
    if 'wlan.ssid' in df.columns:
        df['wlan.ssid'] = df['wlan.ssid'].apply(hex_to_ascii)

    # Save output
    output_dir = os.path.dirname(pcap_file)
    output_file = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(pcap_file))[0]}_ascii.csv")
    df.to_csv(output_file, index=False)
    print(f"Converted: {pcap_file} → {output_file}")
    return True

# Input directory
input_directory = "Your Directory"  # Replace with your actual directory
unziped = []

# Walk through directory and process .pcap/.zip files
for root, subFolders, files in os.walk(input_directory):
    for file in files:
        file_path = os.path.join(root, file)

        if file.endswith((".pcap", ".cap")):
            if not convert_pcap_to_csv(file_path):
                print(f"Failed to convert {file_path} to CSV.")

        elif file.endswith(".zip"):
            with zipfile.ZipFile(file_path, 'r') as myzip:
                for zipC in myzip.namelist():
                    if zipC.endswith(('.pcap', '.cap')):
                        location = myzip.extract(zipC, path=root)
                        unziped.append(location)
                        if not convert_pcap_to_csv(location):
                            print(f"Failed to convert {location} to CSV.")

# Clean up temporary extracted files
for x in unziped:
    os.remove(x)