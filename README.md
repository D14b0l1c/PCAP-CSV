# PCAP-CSV

This Python script is designed to convert pcap (Packet Capture) files to CSV (Comma-Separated Values) format using the Wireshark command-line tool, tshark. Here's a brief description of what the code does:

1. Import Necessary Libraries: 
The script imports required libraries, including `subprocess` for executing shell commands, `pandas` for handling data in DataFrame format, `os` for interacting with the file system, and `zipfile` for handling zip files.

2. Define Hexadecimal to ASCII Conversion Function: 
The script defines a function `hex_to_ascii` to convert hexadecimal SSID (Service Set Identifier) to ASCII (American Standard Code for Information Interchange).

3. Define Pcap to CSV Conversion Function:
The script defines a function `convert_pcap_to_csv` to execute the tshark command and convert pcap files to CSV format. This function takes a pcap file path as input and returns `True` if conversion is successful, otherwise `False`.

4. Define Input Directory Path: 
The input directory path where pcap files are located is defined.

5. Search and Convert Pcap Files: The script searches the input directory for pcap files and iterates over each file found. For each pcap file, it calls the `convert_pcap_to_csv` function to convert it to CSV format. If the conversion fails, an error message is printed.

6. Handle Zip Archives: 
If zip archives containing pcap files are found in the input directory, the script extracts the pcap files from the zip archives and converts them to CSV format similar to the previous step.

7. Clean Up Extracted Files:
After conversion, the extracted pcap files are removed to clean up the directory.

Overall, this script automates the process of converting pcap files to CSV format, making it easier to analyze network traffic.
