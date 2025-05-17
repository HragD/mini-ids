
This is a basic network-based Intrusion Detection System (IDS) built in Python using Scapy.
It works on Windows and monitors live network traffic for:

SYN flood attempts
Port scan behavior
Blacklisted IPs

 Requirements

- Python 3.x
- scapy

Install dependencies:
```
pip install scapy
```

---

How to Run

1. Open CMD **as Administrator**
2. Navigate to the project folder
3. Run:
```
python mini_ids.py
```

---

To simulate an attack, try scanning the machine from another device:
```
nmap -sS <your-ip>
```
---

Features

- Real-time packet sniffing
- Blacklist IP detection
- Tracks SYN packet count per IP
- Detects suspicious port probing

---

**This tool is for educational and lab use only. Do **not** use it to monitor or interfere with networks you don't own or control.**

---

