# shadowsweep
ShadowSweep – Android Threat Analysis Tool

ShadowSweep is a Python-based forensic tool for Android threat detection and analysis.
It was developed as part of an internship project at Indira Gandhi Delhi Technical University for Women (IGDTUW).

The tool detects hidden apps, malware, and suspicious behavior by analyzing Android device logs.
It also integrates OSINT (Open Source Intelligence) techniques such as WHOIS, IP lookups, and dark web scanning (via Tor), presented through an interactive Streamlit dashboard.

# Features

Log Analysis – Extracts and analyzes Android logs using ADB.

OSINT Integration – WHOIS, IP lookups, and dark web scanning via Tor.

Interactive Dashboard – Streamlit-based UI for easy navigation.

Exportable Reports – Generate CSV reports for documentation.

Network-level Analysis – Supports extended forensic investigation.

# Tech Stack

Python

Streamlit

Android Debug Bridge (ADB)

Tor Browser / Tor Service (for dark web scanning)

Requests, WHOIS libraries

# Installation & Usage
1. Clone the repository
git clone https://github.com/manpreetk24k/shadowsweep.git
cd shadowsweep

2. Install dependencies & run imp commands in vs code like streamlit

3. Install & Run Tor

Download Tor Browser and amke sure your tor browser is running behind the application for dark web scanning then check status of tor by clicking the tor connection button on left side.

4. Connect Android Device

Enable USB debugging on your phone and connect via USB.
Verify connection:

adb devices

5. Run the Application
streamlit run app.py

# Outputs

Malware/hidden app detection results

WHOIS/IP lookup information

Dark web scanning results (via Tor)

CSV reports for offline analysis


# Skills Demonstrated

Digital Forensics

Android Debug Bridge (ADB)

OSINT (WHOIS, IP lookup, dark web scanning)

Python Programming

Streamlit Dashboard Development
