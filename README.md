# 🔐 EELP — Evolutionary Efficient Lightweight Protocol

Практическая **reference-реализация** протокола EELP в этом репозитории.

> В исходной концепции заявлены X25519 и ChaCha20-Poly1305. В текущем окружении (без внешних крипто-библиотек) реализован dependency-free прототип на стандартной библиотеке Python: DH + HMAC/HKDF + stream-XOR. Архитектура и шаги протокола сохранены, криптопримитивы можно заменить на production-аналоги без изменения state machine.

## Что реализовано

- `ClientHello` / `ServerHello` (1-RTT handshake)
- Контекст-связывание `version|suite` для downgrade protection
- Эфемерный DH обмен ключом (демо-замена X25519)
- HKDF-SHA256 (собственная реализация) для вывода сессионных ключей
- MAC в `ServerHello` на базе PSK для защиты от MITM-подмены
- Шифрование payload через stream-XOR + тег целостности HMAC
- Anti-replay: sliding window на 32 пакета
- Lightweight rekey через HKDF
- State machine: `INIT -> HELLO_SENT -> ESTABLISHED -> REKEYING -> CLOSED`

## Структура

- `eelp/protocol.py` — реализация протокола и крипто-примитивов демо-уровня
- `tests/test_protocol.py` — тесты handshake / шифрования / replay / tamper

## Быстрый запуск

```bash
python -m unittest -v
```

## Пример использования

```python
from eelp.protocol import EELPPeer

psk = b"demo-static-psk-for-mac"
client = EELPPeer(psk=psk, role="client")
server = EELPPeer(psk=psk, role="server")

client_hello = client.create_client_hello()
server_hello = server.process_client_hello(client_hello)
client.process_server_hello(server_hello)

packet = client.encrypt(b"temperature=23", aad=b"topic:sensor")
plaintext = server.decrypt(packet, aad=b"topic:sensor")
print(plaintext)
```

## Ограничения

- Это прототип для практической демонстрации протокольной логики.
- Криптография не production-grade (для production заменить примитивы на X25519 + ChaCha20-Poly1305 + battle-tested library).
- Нет сетевого транспорта (только протокольный слой).

## License

MIT
