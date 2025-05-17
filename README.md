# 🛡️ Mini IDS - Intrusion Detection System (Python)

This is a basic network-based Intrusion Detection System (IDS) built in Python using Scapy.
It works on Windows and monitors live network traffic for:

- 🚨 SYN flood attempts
- 🔍 Port scan behavior
- ⚠️ Blacklisted IPs

---

## 📦 Requirements

- Python 3.x
- scapy

Install dependencies:
```
pip install scapy
```

---

## ▶️ How to Run

1. Open CMD **as Administrator**
2. Navigate to the project folder
3. Run:
```
python mini_ids.py
```

---

## 🧪 Testing

To simulate an attack, try scanning the machine from another device:
```
nmap -sS <your-ip>
```

You'll get alerts like:
```
🚨 POSSIBLE SYN FLOOD from 192.168.1.5
🔍 Possible Port Scan: 192.168.1.5 → Port 80
```

---

## ⚙️ Features

- Real-time packet sniffing
- Blacklist IP detection
- Tracks SYN packet count per IP
- Detects suspicious port probing

---

## ⚠️ Legal Note

This tool is for educational and lab use only. Do **not** use it to monitor or interfere with networks you don't own or control.

---

## 💡 Upgrades You Can Add

- Alert logging to a file
- Desktop notifications or sound alerts
- Email alerts
- GUI interface (Tkinter or PyQt)

Happy hacking 🔐
