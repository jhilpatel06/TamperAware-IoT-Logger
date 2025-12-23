# IoT Forensic Memory Framework

A memory-based IoT forensic framework designed to ensure **tamper-evident logging** on resource-constrained embedded devices.  
The system focuses on preserving **integrity, authenticity, and traceability** of sensor data stored in non-volatile memory.

---

## 📌 Motivation

In many IoT deployments, sensor logs are assumed to be trustworthy by default.  
However, data stored on external memory (e.g., SD cards) can be:
- modified,
- deleted,
- injected,
- or replaced  
without leaving any indication of tampering.

This becomes a critical issue in **forensic investigations**, especially under legal frameworks such as the **Indian IT Act** and **Section 65B of the Indian Evidence Act**, where data integrity is mandatory.

---

## 🧠 Core Idea

This framework introduces a **memory-resident forensic protection layer** using:

- Cryptographic hash chaining
- Secure log sequencing
- Tamper detection and verification mechanisms

Each log entry is **cryptographically linked** to the previous one, making unauthorized modification detectable.

---

## ⚙️ System Architecture

1. ESP32 collects sensor data
2. Log entries are created in memory
3. SHA-256 hash is computed for each entry
4. Each entry stores the hash of the previous entry
5. Logs are written to SD card
6. Verification detects any tampering or breaks in the chain

---

## 🔐 Security Features

- Hash-based log chaining (SHA-256)
- Tamper detection for modified or injected logs
- Protection against silent data manipulation
- Forensic verification support

---

## 🧪 Tampering Simulation

The framework was tested against realistic attack scenarios:
- Manual SD card file modification
- Log injection
- Remote tampering via HTTP requests
- Network traffic inspection using Wireshark

Any alteration resulted in **hash chain verification failure**, proving tamper detection effectiveness.

---

## 🛠️ Technologies Used

- ESP32
- SD Card (FAT filesystem)
- SHA-256 Cryptographic Hashing
- HTTP-based log access
- Wireshark (network analysis)
- Embedded C / Arduino Framework

---

## 📊 Outcomes

- Successful detection of single-bit and multi-entry tampering
- Improved trustworthiness of IoT-generated evidence
- Demonstrated forensic readiness of low-cost IoT hardware

---
## 🎥 Demo Video

A demonstration of the complete system workflow, including log generation, hash chaining, tampering simulation, and forensic verification, is available at the link below:

🔗 **Demo Video:** https://youtu.be/pL5St93XZ0g?si=cstGCZb7T-Y8bX20

The video showcases:
- Real-time data logging on ESP32  
- Secure hash-chain based log storage  
- Manual and remote tampering attempts  
- Detection of integrity violations during verification  


## 📚 Learning & Insights

- Practical challenges of forensic logging on constrained devices
- Importance of cryptographic integrity in embedded systems
- Legal relevance of secure data handling in IoT
- Real-world attack surface analysis for IoT deployments

---

## 🚀 Future Enhancements

- Secure timestamping using trusted time sources
- Encrypted log storage
- Blockchain-backed evidence anchoring
- Cloud-based forensic verification dashboard
- Key management and access control

---

## 👤 Author

**Jhil Patel**  

