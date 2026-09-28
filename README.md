# SecBank: Application-Layer Integrity Verifier 🏦🛡️

> **Disclaimer:** This project is developed for educational purposes as part of the "Security in Computer Systems and Internet" course (PAI-1 IntegriDos). It implements cryptographic security controls entirely at the application layer over insecure networks (without TLS/HTTPS).

## 📌 Project Overview

SecBank is a distributed client-server architecture designed to securely process financial transactions over public, unencrypted networks. Because transport-layer security (TLS/SSL) is strictly disabled by design, this API implements robust cryptographic mechanisms to ensure data integrity, authenticity, and protection against common network-level attacks.

## 🔐 Security Features Implemented

*   **Integrity & Authenticity:** Payload signing using **HMAC-SHA256** to prevent Man-in-the-Middle (MitM) data tampering.
*   **Anti-Replay Protection:** Implementation of unique **UUIDv4 Nonces** and **Timestamps** validated against a server-side state registry to drop duplicated or delayed frames.
*   **Key Derivation:** Secure password hashing and credential storage using **Argon2id** with unique per-user salts.
*   **Timing Attack Mitigation:** Strict use of **constant-time comparison** algorithms (`secrets.compare_digest`) for MAC and hash validations to prevent side-channel timing attacks.

## 🛠️ Technology Stack

*   **Architecture:** REST API (HTTP/1.1 POST without encryption)
*   **Backend:** Python 3.10+ / FastAPI / Uvicorn
*   **Cryptography:** `cryptography`, `argon2-cffi`, `secrets` standard library

## 🚀 Quickstart & Deployment

### 1. Clone the repository
```bash
git clone [https://github.com/yourusername/secbank-integrity-verifier.git](https://github.com/yourusername/secbank-integrity-verifier.git)
cd secbank-integrity-verifier
