# 🚨 Real-Time Intrusion Detection System (IDS)

This project captures live network packets using **C++ (libpcap)**, detects anomalies, and streams results to a **real-time dashboard** built with **Node.js and Socket.IO**.

---

## 🔍 Features

* 📡 Live packet capture from network interface (e.g., `eth0`)
* ⚡ Real-time anomaly detection:

  * Same Source & Destination IP
  * Oversized packets
  * Statistical deviation (outliers)
  * Port scan detection
  * SYN flood detection
  * ICMP flood detection
* 📊 Live dashboard visualization (browser-based)
* 📁 Logs stored in `.ndjson` format
* 📈 Accuracy testing using Python script

---

## 🛠️ Technologies Used

* **C++** → libpcap, jsoncpp
* **Node.js** → Express, Socket.IO
* **Frontend** → HTML, CSS, JavaScript
* **Python** → Accuracy evaluation

---

## ⚙️ Installation

### 1. Install Dependencies (WSL / Ubuntu)

```bash
sudo apt update
sudo apt install g++ libpcap-dev libjsoncpp-dev nodejs npm python3
```

---

### 2. Install Node Packages

```bash
npm install
```

---

## 🚀 How to Run

### Step 1 — Compile IDS

```bash
g++ ids.cpp -o ids -lpcap -ljsoncpp -std=c++17 -O2
```

---

### Step 2 — Give Permissions (Important)

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./ids
```

---

### Step 3 — Run Server

```bash
INTERFACE=eth0 node server.js
```

👉 If permission error:

```bash
sudo INTERFACE=eth0 node server.js
```

---

### Step 4 — Open Dashboard

Open in browser:

```
http://localhost:3000
```

---

## 📊 Accuracy Testing

After running the system and collecting packets:

```bash
python3 accuracy_test.py
```

Example Output:

```
Anomaly       TP    FP    FN     TN    Prec  Recall      F1     Acc
---------------------------------------------------------------
statdev       201    18    14   4767   91.78%  93.49%  92.63%
```

---

## 🧪 Generate Traffic (for testing)

```bash
ping google.com
curl http://example.com
```

Port scan test:

```bash
sudo apt install nmap
nmap -p 1-1000 localhost
```

---

## 📁 Project Structure

```
ids-project/
│
├── ids.cpp              # Packet capture + detection (C++)
├── ids                  # Compiled binary
├── server.js            # Node.js backend
├── accuracy_test.py     # Evaluation script
├── ids_log.ndjson       # Captured logs
├── public/
│   └── index.html       # Dashboard UI
```

---

## ⚠️ Notes

* Works best on **Linux / WSL2**
* Requires **root permissions** for packet capture
* `eth0` is default interface in WSL

---

## 👩‍💻 Author

**Bhumika Pundir**

---

## ⭐ Future Improvements

* Machine Learning-based anomaly detection
* Advanced attack simulation
* Alert notifications system
* Deployment on cloud

---
