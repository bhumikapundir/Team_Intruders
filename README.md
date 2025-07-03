# Real-Time Intrusion Detection System (IDS)

This project captures live network packets using C++ (`libpcap`), detects anomalies, and sends data to a live dashboard using **Socket.IO** and **Node.js**.

# Notes:
- Make sure your network interface is active (e.g., `eth0`).
- Run with root permission if needed: `sudo ./ids`

# What It Does
- Captures packets from network interface (e.g., `eth0`)
- Detects anomalies like:
- Source IP same as Destination IP
- Oversized packets
- Statistically unusual sizes (outliers)
- Outputs data in **JSON format**
- Visualizes data on a **live dashboard in your browser**

# Technologies Used
- C++ (`libpcap`, JSONCPP)
- Node.js + Express + Socket.IO
- HTML/CSS/JS frontend

# How to Run
1. "Install dependencies:"
   - C++: `libpcap`, `libjsoncpp`
   - Node.js: `npm install express socket.io`
2. "Compile the C++ program"
3. "Run the Node.js server"
4. "Open the dashboard"

http://localhost:3000

project-folder/
│
├── ids.cpp # C++ packet capture + JSON output
├── server.js # Node.js server with Socket.IO
├── public/
│ └── index.html # Frontend dashboard





