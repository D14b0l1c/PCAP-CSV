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
    # Define tshark command
    tshark_command = [
        "tshark",
        "-r",
        pcap_file,
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "frame.time",
        "-e",
        "wlan_radio.signal_db",
        "-e",
        "wlan_radio.channel",
        "-e",
        "wlan.ssid",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "ip.ttl",
        "-e",
        "wlan.bssid",
        "-e",
        "wlan.sa",
        "-e",
        "wlan.ta",
        "-e",
        "wlan.ra",
        "-e",
        "wlan.da",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.flags",
        "-e",
        "_ws.col.Info",
        "-e",
        "frame.len",
        "-e",
        "frame.time_delta_displayed",
        "-e",
        "ppi_gps.lat",
        "-e",
        "ppi_gps.lon",
        "-e",
        "ppi_gps.alt",
        "-E",
        "header=y",
        "-E",
        "separator=|"
    ]

    # Execute tshark command and capture output
    process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if error:
        print(f"Error occurred while executing tshark command for {pcap_file}: {error.decode()}")
        return False

    # Convert the output to DataFrame
    output_lines = output.decode().split('\n')
    header = output_lines[0].split('|')
    data = [line.split('|') for line in output_lines[1:] if line.strip()]
    df = pd.DataFrame(data, columns=header)

    # Define data types for columns with mixed types
    dtype_mapping = {
        "wlan.ssid": str,
        "wlan_radio.channel": str,
        "tcp.srcport": str,
        "tcp.dstport": str,
        # Add other columns here with mixed types if needed
    }

    # Convert hexadecimal SSID to ASCII
    df['wlan.ssid'] = df['wlan.ssid'].apply(hex_to_ascii)

    # Save the modified DataFrame to a CSV file
    output_dir = "Your Directory"
    output_file = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(pcap_file))[0]}_ascii.csv")
    df.to_csv(output_file, index=False)
    return True

# Define input directory path
input_directory = "Your Directory"
unziped = []

# Search input directory for pcap files and convert them to csv
for root, subFolders, files in os.walk(input_directory):
	for file in files:
		if (".pcap" in file or ".cap" in file):
			pcap_file = os.path.join(root, file)
			if not convert_pcap_to_csv(pcap_file):
				print(f"Failed to convert {pcap_file} to CSV.")
		elif (".zip" in file):
			with zipfile.ZipFile(root + '/' + file) as myzip: 
				for zipC in myzip.namelist():
					if ('.pcap' in zipC or '.cap' in zipC):
						location=myzip.extract(zipC)
						unziped.append(location)
						if not convert_pcap_to_csv(location):
							print(f"Failed to convert {location} to CSV.")
for x in unziped:
	os.remove(x)
