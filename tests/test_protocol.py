import unittest

from eelp.protocol import EELPPeer, ProtocolState


class EELPProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.psk = b"demo-static-psk-for-mac"

    def _handshake(self):
        client = EELPPeer(psk=self.psk, role="client")
        server = EELPPeer(psk=self.psk, role="server")

        ch = client.create_client_hello()
        sh = server.process_client_hello(ch)
        client.process_server_hello(sh)

        self.assertEqual(client.state, ProtocolState.ESTABLISHED)
        self.assertEqual(server.state, ProtocolState.ESTABLISHED)
        return client, server

    def test_handshake_and_encryption(self):
        client, server = self._handshake()
        packet = client.encrypt(b"sensor:42", aad=b"topic=temp")
        plain = server.decrypt(packet, aad=b"topic=temp")
        self.assertEqual(plain, b"sensor:42")

    def test_replay_protection(self):
        client, server = self._handshake()
        packet = client.encrypt(b"payload")
        self.assertEqual(server.decrypt(packet), b"payload")
        with self.assertRaisesRegex(ValueError, "replay"):
            server.decrypt(packet)

    def test_mac_detects_tampering(self):
        client = EELPPeer(psk=self.psk, role="client")
        server = EELPPeer(psk=self.psk, role="server")
        ch = client.create_client_hello()
        sh = bytearray(server.process_client_hello(ch))

        # corrupt server hello payload
        sh[-3] = ord("0") if sh[-3] != ord("0") else ord("1")
        with self.assertRaises(Exception):
            client.process_server_hello(bytes(sh))


if __name__ == "__main__":
    unittest.main()
