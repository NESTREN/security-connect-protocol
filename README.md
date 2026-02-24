# 🔐 EELP — Evolutionary Efficient Lightweight Protocol

<p align="center">
  <img alt="Status" src="https://img.shields.io/badge/status-prototype-4c1?style=for-the-badge" />
  <img alt="Security" src="https://img.shields.io/badge/security-forward_secrecy-success?style=for-the-badge" />
  <img alt="Handshake" src="https://img.shields.io/badge/handshake-1RTT-brightgreen?style=for-the-badge" />
  <img alt="Anti Replay" src="https://img.shields.io/badge/defense-anti--replay-blue?style=for-the-badge" />
  <img alt="Crypto Agility" src="https://img.shields.io/badge/design-crypto_agility-purple?style=for-the-badge" />
  <img alt="Python" src="https://img.shields.io/badge/python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey?style=for-the-badge" />
</p>

<p align="center">
  <b>Minimalistic • Evolvable • Secure-by-Design • Embedded Friendly</b>
</p>

---

## 🌍 Что это

**EELP** — лёгкий протокол защищённого канала для устройств с ограниченными ресурсами (IoT, embedded, edge-gateway).

В репозитории реализован **практический reference-прототип**:

- 1-RTT handshake
- state machine протокола
- защита от replay
- защита от downgrade через context binding
- шифрование прикладных сообщений
- lightweight rekey

> ⚠️ Важно: текущая реализация — демонстрационная, ориентирована на понятную и воспроизводимую протокольную логику. Для production следует заменить криптопримитивы на промышленный стек (например, X25519 + ChaCha20-Poly1305 из battle-tested библиотек).

---

## 🧱 Архитектура и крипто-стек (текущий прототип)

| Слой | Используется в репозитории | Назначение |
|------|-----------------------------|------------|
| KEX | Ephemeral DH (mod p) | общий секрет с Forward Secrecy-подходом |
| KDF | HKDF-SHA256 | вывод сессионных ключей |
| Integrity | HMAC-SHA256 | MAC handshake + теги пакетов |
| Encryption | Stream-XOR (HMAC keystream) | шифрование payload |
| Anti-Replay | Sliding Window (32) | отсев повторов пакетов |

---

## 🤝 Handshake (1 RTT)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server

    C->>S: ClientHello(version, suite, random_c, eph_pub_c)
    S->>S: Derive shared secret
    S->>S: HKDF(context = version|suite)
    S->>C: ServerHello(random_s, eph_pub_s, mac_psk)
    C->>C: Verify MAC + derive keys
    Note over C,S: State = ESTABLISHED
```

### Что защищает handshake

- **MITM-подмена**: через MAC `ServerHello` (на PSK).
- **Downgrade**: версия/сьют включены в HKDF context.
- **FS-подход**: используются эфемерные ключи на сессию.

---

## 🧠 State Machine

```mermaid
stateDiagram-v2
    [*] --> INIT
    INIT --> HELLO_SENT: create_client_hello()
    INIT --> ESTABLISHED: process_client_hello()
    HELLO_SENT --> ESTABLISHED: process_server_hello()
    ESTABLISHED --> REKEYING: lightweight_rekey()
    REKEYING --> ESTABLISHED
    ESTABLISHED --> CLOSED: close()
```

---

## ⚔️ Сценарии атак и защита

### 1) MITM (подмена handshake)

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Attacker
    participant S as Server

    C->>A: ClientHello
    A->>S: Modified ClientHello
    S->>A: ServerHello + MAC
    A->>C: Forged ServerHello
    C-->>A: MAC validation failed
```

✅ Защита: MAC на `ServerHello` + привязка к параметрам handshake.

---

### 2) Downgrade (принудительный старый suite/version)

```mermaid
flowchart LR
    C[Client wants v1|suiteA] --> A[Attacker]
    A -->|tries rewrite| S[Server]
    S --> A --> C
    C --> X[HKDF context mismatch]
```

✅ Защита: `context = version|suite`, изменение параметров ломает проверку целостности сессии.

---

### 3) Replay (повтор зашифрованного пакета)

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Attacker
    participant S as Server

    C->>S: Packet(counter=42)
    A->>S: Replayed Packet(counter=42)
    S-->>A: Rejected (already seen)
```

✅ Защита: Sliding Window + bitmap на 32 последних counter.

---

## 🚦 Реальное применение: шифрование трафика датчиков

Ниже пример практического сценария: **датчик температуры** шифрует данные перед отправкой на шлюз.

```mermaid
flowchart LR
    D[Sensor Device] -->|EELP encrypted packet| G[Secure Gateway]
    G -->|decrypted payload| B[Backend / Broker]
    B --> U[Monitoring UI]
```

### Пример кода

```python
from eelp.protocol import EELPPeer

psk = b"demo-static-psk-for-mac"

# Инициализация ролей
client = EELPPeer(psk=psk, role="client")   # датчик
server = EELPPeer(psk=psk, role="server")   # шлюз

# 1-RTT handshake
client_hello = client.create_client_hello()
server_hello = server.process_client_hello(client_hello)
client.process_server_hello(server_hello)

# Шифрование телеметрии
packet = client.encrypt(
    b'{"device":"temp-01","value":23.7,"unit":"C"}',
    aad=b"topic:sensors/temp"
)

# Расшифровка на шлюзе
plaintext = server.decrypt(packet, aad=b"topic:sensors/temp")
print(plaintext.decode())
```

---

## 🗂 Структура репозитория

- `eelp/protocol.py` — core-реализация протокола
- `eelp/__init__.py` — экспорт API
- `tests/test_protocol.py` — тесты handshake/encryption/replay/tamper

---

## ▶️ Быстрый старт

```bash
python -m unittest discover -s tests -v
```

---

## 📌 Ограничения прототипа

- Reference-уровень, не production-ready crypto stack.
- Нет встроенного транспорта (UDP/TCP/Serial) — только протокольный слой.
- Нет долгоживущего хранилища сессий и автоматического key rotation policy.

---

## 👤 Автор

**nestren**

Идея и направление протокола: эволюционный lightweight secure channel для embedded и IoT.

---

## 📜 License

MIT
