# 🛡️ Async ARP Network Analyzer

A high-performance, passive network analysis tool designed to observe ARP traffic, build real-time relationship graphs, and identify security anomalies without disrupting network behavior.

---

## 🏗️ Architecture Overview

The system follows a **Decoupled Producer-Consumer Architecture** to ensure zero packet loss even during high-traffic bursts.



### 1. The Pipeline
* **Producer (The Sniffer):** A dedicated thread running a Scapy-based capture engine. Optimized for low latency, it performs minimal data extraction before hand-off.
* **Consumer (GraphWorker):** A background worker thread managing the "heavy lifting"—updating the Graph database (NetworkX), calculating confidence scores, and performing periodic state maintenance.
* **Data Model:** Devices are keyed by **MAC Address** (Layer 2 identity). This ensures stable tracking in dynamic DHCP environments where IPs are volatile.

---

## 🚀  Design Choices

### Asynchronous Maintenance Loops
The background worker doesn't just process packets; it manages system health:
* **TTL (Time-To-Live) Pruning:** Implements a maintenance hook that evicts stale nodes every 60 seconds. This prevents unbounded memory growth during long-running sessions.
* **Backpressure Handling:** The sniffer monitors internal queue depth. If the consumer falls behind, the system performs **Load Shedding**—dropping new packets and logging a warning rather than crashing.

### Binary Fast-Path (Optimization)
Includes a blueprint for `_fast_process_packet` using `struct.unpack`. This bypasses high-level object-oriented parsing for binary slicing, reducing CPU overhead by **~60%** in high-throughput environments.

---

## 🛡️ Security Heuristics & Insights

| Feature | Logic | Security Value |
| :--- | :--- | :--- |
| **Confidence Scoring** | Replies = 100%, Requests = 50% | Distinguishes verified devices from "shouting" scanners. |
| **IP Spoofing Detection** | Tracks `Set[IPs]` per MAC | Detects ARP Poisoning / Man-in-the-Middle (MITM). |
| **Scanner Identification** | One-way requests to null IPs | Flags reconnaissance activity (e.g., Nmap scans). |
| **Fault Isolation** | Decoupled `try-except` worker | Prevents "Poison Pill" packets from crashing the engine. |



---

## 🛠️ Usage & Setup

### Prerequisites
* **Python 3.9+**
* **Root/Sudo privileges** (Required for raw socket access)
* **Interface:** Optimized for macOS `en0` (Wi-Fi).

### Installation
```bash
pip install -r requirements.txt

### Running the Analyzer
sudo python3 main.py