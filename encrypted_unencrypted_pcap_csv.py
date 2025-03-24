import subprocess
import pandas as pd
import os
import zipfile

# Function to convert hexadecimal SSID to ASCII
def hex_to_ascii(hex_str):
    try:
        ascii_str = bytes.fromhex(hex_str).decode('utf-8')
        return ascii_str
    except Exception as e:
        return str(e)

# Function to execute tshark command and convert pcap to csv
def convert_pcap_to_csv(pcap_file):
    # Define tshark command with -n (disable name resolution)
    tshark_command = [
        "tshark",
        "-n",  # Disable name resolution for speed/raw IPs
        "-r", pcap_file,  # Read from input file
        "-T", "fields",  # Output only selected fields

        # === Frame/Metadata ===
        "-e", "frame.number",  # Packet number in the capture
        "-e", "frame.time_epoch",  # Timestamp in UNIX epoch time format

        # === Wireless Signal Info ===
        "-e", "wlan_radio.signal_db",  # Signal strength in dBm
        "-e", "wlan_radio.channel",  # Channel on which the packet was captured

        # === SSID and Protocol ===
        "-e", "wlan.ssid",  # SSID (hex-encoded in some mgmt frames)
        "-e", "_ws.col.Protocol",  # High-level protocol (TCP, ARP, etc.)

        # === IP/Network Layer ===
        "-e", "ip.ttl",  # IP TTL field

        # === MAC Addresses ===
        "-e", "wlan.bssid",  # Access point MAC
        "-e", "wlan.sa",  # Source MAC address
        "-e", "wlan.ta",  # Transmitter MAC address
        "-e", "wlan.ra",  # Receiver MAC address
        "-e", "wlan.da",  # Destination MAC address

        # === IP Addresses ===
        "-e", "ip.src",  # Source IP address
        "-e", "ip.dst",  # Destination IP address

        # === TCP Ports and Flags ===
        "-e", "tcp.srcport",  # Source TCP port
        "-e", "tcp.dstport",  # Destination TCP port
        "-e", "tcp.flags",  # TCP control flags (e.g. SYN, ACK)

        # === Frame Summary ===
        "-e", "_ws.col.Info",  # Info column
        "-e", "frame.len",  # Frame length in bytes
        "-e", "frame.time_delta_displayed",  # Time since previous displayed packet

        # === GPS Fields (if available) ===
        "-e", "ppi_gps.lat",  # Latitude
        "-e", "ppi_gps.lon",  # Longitude
        "-e", "ppi_gps.alt",  # Altitude

        # === Output Format Options ===
        "-E", "header=y",  # Include column headers
        "-E", "separator=,"  # Use comma as delimiter
    ]

    # Execute tshark command and capture output
    process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if error:
        print(f"Error occurred while executing tshark command for {pcap_file}: {error.decode()}")
        return False

    # Decode and structure the output into a DataFrame
    output_lines = output.decode().split('\n')
    if not output_lines or not output_lines[0].strip():
        print(f"No data extracted from {pcap_file}")
        return False

    header = output_lines[0].split('|')
    data = [line.split('|') for line in output_lines[1:] if line.strip()]
    df = pd.DataFrame(data, columns=header)

    # Define data types for fields with possible mixed types
    dtype_mapping = {
        "wlan.ssid": str,
        "wlan_radio.channel": str,
        "tcp.srcport": str,
        "tcp.dstport": str,
        # Add more if needed
    }

    # Convert hexadecimal SSID to ASCII
    if 'wlan.ssid' in df.columns:
        df['wlan.ssid'] = df['wlan.ssid'].apply(hex_to_ascii)

    # Save CSV to the same folder as the input pcap
    output_dir = os.path.dirname(pcap_file)
    output_file = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(pcap_file))[0]}_ascii.csv")
    df.to_csv(output_file, index=False)
    print(f"Converted: {pcap_file} → {output_file}")
    return True

# Define the input directory
input_directory = "Your Directory"  # Replace with your actual directory path
unziped = []

# Traverse the directory
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

# Clean up extracted PCAPs
for x in unziped:
    os.remove(x)