# Live Network Packet Capture Tool

## Overview

This project is a **Live Network Packet Capture Tool** built using Python and Flask. It captures network packets in real-time, analyzes their threat levels, and displays the information dynamically on a web interface. Users can start and stop the packet capture, view packet details, and clear logs as needed. 

## Features

- **Real-Time Packet Capture**: Continuously captures packets from your network.
- **Threat Level Analysis**: Classifies packets into threat levels (High, Medium, Low) with color-coded visual indicators.
- **Dynamic Web Interface**: Utilizes Flask to serve a responsive web interface that updates packet data in real-time.
- **Packet Details**: Displays detailed information about each captured packet, including timestamps, source/destination IPs, and ports.
- **Save Packet Data**: Ability to save specific packet data for later analysis.

## Technologies Used

- **Python**: The main programming language for the backend.
- **Flask**: A lightweight web framework for serving the application.
- **Scapy**: A powerful Python library for packet manipulation and capture.
- **HTML/CSS/JavaScript**: For building the user interface.

## Prerequisites

- Python 3.x
- Flask
- Scapy
- Access to network interface for packet capturing (admin privileges may be required).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/live-packet-capture.git
   cd live-packet-capture
2. Create a virtual environment (optional but recommended):
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`

3. Install the required packages:
pip install Flask scapy
Note: Ensure that you have WinPcap or Npcap installed if you are on Windows, as Scapy relies on these libraries for packet capturing.

## Usage
Run the application:

python app.py
Open a web browser and navigate to:

http://127.0.0.1:5000

## Use the buttons on the webpage to:

Start Capture: Begin capturing network packets.
Stop Capture: Stop capturing packets.
Clear Logs: Clear the displayed packet logs.
The captured packets will appear in a table, showing their timestamps, threat levels, and other details.

## Customization
You can customize the following aspects of the application:

Packet Filters: Modify the packet filtering criteria in the Scapy capture function as per your requirements.
Threat Level Logic: Adjust how packets are classified into different threat levels based on your analysis needs.
Frontend Styles: Update the CSS files in the static folder to change the appearance of the web interface.

## Contributing
Contributions are welcome! Please create a pull request or open an issue for any enhancements or bug fixes.

Acknowledgments
Flask
Scapy
Npcap
WinPcap
## Contact
For questions or support, feel free to reach out to [rahul2472001@gmail.com].
