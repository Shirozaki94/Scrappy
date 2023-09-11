# Scrappy

**Scrappy** is a Python application designed to analyze network traffic and provide insights into incoming packets. It uses the Scapy library for packet manipulation and analysis.

## Features

- Real-time packet capturing and analysis.
- Graphical representation of data.
- Detailed information on top IPs and their corresponding ports.

## Prerequisites

- Python 3.x
- Required Python libraries (Scapy, Matplotlib, Pandas)
- **Administrator privileges** for packet capturing

## Getting Started

1. Clone the repository to your local machine.
2. Install the required Python libraries:
   ```bash
   pip install scapy matplotlib pandas

Use the GUI to start and stop packet capturing, view packet details, and save information.
Usage
Click the "Start" button to begin packet capturing.
Click the "Stop" button to halt packet capturing.
View real-time data on the GUI.
Click "Save Info" to export packet details to an Excel file.
Known Issues
If packet capturing is not functioning, ensure the script is run with administrator privileges.
Contributing
Feel free to open issues or submit pull requests to help improve Scrappy.

License
This project is licensed under the MIT License.

Note: Scrappy is provided as-is and is not responsible for any unauthorized use or access to network data. Please use responsibly and in compliance with applicable laws and regulations.
