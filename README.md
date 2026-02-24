# 🔐 EELP — Evolutionary Efficient Lightweight Protocol

<p align="center">

![Status](https://img.shields.io/badge/status-research--prototype-4c1?style=for-the-badge)
![Security](https://img.shields.io/badge/security-forward--secrecy-success?style=for-the-badge)
![Crypto](https://img.shields.io/badge/crypto-X25519%20%7C%20ChaCha20-blueviolet?style=for-the-badge)
![Handshake](https://img.shields.io/badge/handshake-1RTT-brightgreen?style=for-the-badge)
![Flash](https://img.shields.io/badge/flash-25--35KB-orange?style=for-the-badge)
![RAM](https://img.shields.io/badge/RAM-4--8KB-yellow?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-IoT%20%7C%20Embedded-informational?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-lightgrey?style=for-the-badge)

</p>

<p align="center">
Minimalistic • Evolvable • Secure • Embedded-Optimized
</p>

---

# 📖 Overview

**EELP** — лёгкий криптографический протокол для устройств с ограниченными ресурсами.

Разработан для:

- IoT-устройств  
- микроконтроллеров  
- low-power сетей  
- embedded-гейтвеев  

Цель — обеспечить защищённое соединение с минимальной реализацией и возможностью крипто-эволюции.

---

# 🎯 Design Goals

- ≤ 32–64 KB Flash  
- ≤ 8–16 KB RAM  
- 1-RTT handshake  
- Forward Secrecy  
- Anti-Replay  
- Downgrade Protection  
- Crypto Agility  
- Нет X.509  
- Нет ASN.1  
- Минимальный state machine  

---

# 🧠 Cryptographic Stack

| Назначение | Алгоритм |
|------------|----------|
| Key Exchange | X25519 |
| AEAD | ChaCha20-Poly1305 |
| KDF | HKDF-SHA256 |
| Hash | SHA-256 |

---

# 📡 Handshake (1 RTT)

```mermaid
sequenceDiagram
    participant C as Client Device
    participant S as Server Device

    C->>S: ClientHello (version, suite, random, pubkey)
    S->>C: ServerHello (random, pubkey, signature/MAC)
    Note over C,S: Shared Secret via X25519
    Note over C,S: Session Keys via HKDF
```

---

# 🖥 Deployment Scheme (Two Devices)

```mermaid
flowchart LR
    subgraph Device_A[Embedded Device]
        MCU[Microcontroller]
        EELP1[EELP Stack]
        NET1[Network Interface]
    end

    subgraph Device_B[Secure Gateway]
        CPU[Linux / RTOS]
        EELP2[EELP Stack]
        NET2[Network Interface]
    end

    MCU --> EELP1
    EELP1 --> NET1
    NET1 <--> NET2
    NET2 --> EELP2
    EELP2 --> CPU
```

---

# ⚔ Threat Model — Attack Scenarios

## 1️⃣ MITM Attack Attempt

```mermaid
sequenceDiagram
    participant Client
    participant Attacker
    participant Server

    Client->>Attacker: ClientHello
    Attacker->>Server: Modified Hello
    Server->>Attacker: ServerHello
    Attacker->>Client: Modified Hello
    Note over Client,Server: MAC validation fails
```

**Защита:**
- Подпись / MAC сервера
- HKDF context binding (version + suite)
- Эфемерные ключи (Forward Secrecy)

---

## 2️⃣ Downgrade Attack Attempt

```mermaid
flowchart LR
    Client -->|v3 request| Attacker
    Attacker -->|forces v1| Server
    Server --> Attacker
    Attacker --> Client
```

**Защита:**

Версия включается в HKDF context:

```
context = version || crypto_suite_id
```

Любая модификация версии ломает MAC.

---

## 3️⃣ Replay Attack Attempt

```mermaid
sequenceDiagram
    participant Client
    participant Attacker
    participant Server

    Client->>Server: Packet #42
    Attacker->>Server: Replayed Packet #42
    Note over Server: Counter already seen → rejected
```

**Защита:**

- Монотонный счётчик
- Sliding window (32 пакета)
- Bitmap отслеживания
- Минимум RAM

---

# 🛡 Defense Model Summary

| Attack Type | Defense Mechanism |
|-------------|-------------------|
| MITM | Ephemeral ECDH + MAC |
| Downgrade | HKDF context binding |
| Replay | Counter + Sliding Window |
| Key Compromise | Forward Secrecy |
| Long-term leakage | Rekey rotation |

---

# 🔑 Key Derivation

```text
shared_secret = X25519(client_priv, server_pub)

master_key = HKDF(
    shared_secret,
    client_random || server_random,
    context = version || crypto_suite_id
)
```

---

# 🔐 Encrypted Packet Format

```c
struct {
    uint32  counter;
    uint8   ciphertext[n];
    uint8   tag[16];
}
```

---

# 🔁 Rekey Mechanisms

### Lightweight Rekey

```
session_key = HKDF(session_key, "rekey")
```

### Runtime Upgrade

```c
REKEY_REQUEST {
    new_crypto_suite;
    ephemeral_pubkey;
}
```

---

# 🧬 Crypto Evolution Model

| Version | Crypto |
|----------|--------|
| v1 | X25519 + ChaCha20 |
| v2 | Hybrid PQC |
| v3 | Post-Quantum |

---

# 🏗 State Machine

```mermaid
stateDiagram-v2
    [*] --> INIT
    INIT --> HELLO_SENT
    HELLO_SENT --> ESTABLISHED
    ESTABLISHED --> REKEYING
    REKEYING --> ESTABLISHED
    ESTABLISHED --> CLOSED
```

---

# 🧮 Estimated Footprint

| Component | Flash |
|-----------|--------|
| X25519 | ~8–12 KB |
| ChaCha20-Poly1305 | ~6–8 KB |
| SHA256 + HKDF | ~5 KB |
| Protocol logic | ~5 KB |
| **Total** | ~25–35 KB |

RAM: 4–8 KB

---

# 🔐 Security Properties

- ✔ Forward Secrecy  
- ✔ MITM Resistance  
- ✔ Downgrade Protection  
- ✔ Anti-Replay  
- ✔ Rekey Support  
- ✔ Crypto Agility  

---

# 👤 Author

**Protocol Idea:** nestren  
**Project:** EELP — Evolutionary Efficient Lightweight Protocol  

---

# 📜 License

MIT License

---

⚠ Conceptual cryptographic design. 
