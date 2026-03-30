# AI-Assisted Port Scanner
A GUI TCP port scanner that detects open ports, identifies common services, assigns simple risk levels, and provides beginner-friendly security explanations.

## Features
- Scans a target IP address or hostname for open TCP ports
- Let's the user choose start port, end port, timeout, and scan concurrency
- Resolves hostnames to IP addresses before scanning
- Shows real-time scan progress
- Displays results in a clean table
- Maps common ports to likely services
- Assigns simple risk levels to detected ports
- Provides built-in security explanations and recommendations
- Optionally generates an AI-based report using Hugging Face
- Allows downloading the generated scan report as a text file

## Requirements 
- Python 3.10 or newer
- pip
- Internet connection for scanning remote hosts
- A Hugging Face API token only if you want AI-generated explanations

**Python packages used:**
- Streamlit
- Pandas
- Python-dotenv
- huggingface_hub

## Installation Guide 

**Windows**
```bash
# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux**
```bash
python3 -m venv venv
source venv/bin/activate
```

```bash
#Install dependencies
pip install -r requirements.txt
```

**Add Hugging Face token (Optional)**

Create a `.env` file in the project root and add:
```bash
HF_TOKEN=your_huggingface_token_here
```
If no token is provided, the app will still work using the built-in explanation system.

## Usage Instructions 
```bash
streamlit run app.py
```
1. Enter a target hostname or IP address
2. Select the port range to scan
3. Adjust timeout and worker threads if needed
4. Choose whether to use Hugging Face AI explanations
5. Click **Start Scan**
6. Review the results table, detailed explanations, and generated report
7. Download the report if needed

<img width="1917" height="1132" alt="Image" src="https://github.com/user-attachments/assets/8c709f42-5b5c-494e-bfb6-594b082a7ad6" />
<img width="1914" height="1133" alt="Image" src="https://github.com/user-attachments/assets/e09e6730-6fb8-4fb9-b821-29e556d02b25" />

## Detected Services 

| Port | Service                  |
|------|--------------------------|
| 20   | FTP Data                 |
| 21   | FTP                      |
| 22   | SSH                      |
| 23   | Telnet                   |
| 25   | SMTP                     |
| 53   | DNS                      |
| 67   | DHCP Server              |
| 68   | DHCP Client              | 
| 69   | TFTP                     |
| 80   | HTTP                     |
| 110  | POP3                     |
| 123  | NTP                      |
| 135  | RCP                      |
| 137  | NetBIOS Name Service     |
| 138  | NetBIOS Datagram Service |
| 139  | NetBIOS Session Service  |
| 143  | IMAP                     |
| 161  | SNMP                     |
| 389  | LDAP                     |
| 443  | HTTPS                    |
| 445  | SMB                      |
| 587  | SMTP Submission          |
| 993  | IMAPS                    |
| 995  | POP3S                    |
| 1433 | MSSQL                    |
| 1521 | Oracle DB                |
| 3306 | MySQL                    |
| 3389 | RDP                      |
| 5432 | PostgreSQL               |
| 5900 | VNC                      |
| 6379 | Redis                    |
| 8080 | HTTP-Alt                 |
| 8443 | HTTPS-Alt                |

## Project Structure 

```bash
ai-port-scanner/
├── assets/
│   └── logo.png
├── core/
│   ├── __init__.py
│   ├── explainer.py # Risk levels, recommendations, summaries, and Hugging Face AI integration
│   ├── port_data.py # built-in explanations for known ports
│   ├── scanner.py # host resolution & TCP port scanning logic 
│   └── services.py # common port-to-service mapping
├── .gitignore
├── README.md
├── app.py
└── requirements.txt
```

## Disclaimer
This tool is intended for educational and authorized security testing purposes only. Only scan systems, networks, or hosts that you own or have explicit permission to assess.



