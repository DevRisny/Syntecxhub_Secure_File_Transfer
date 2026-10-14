import unittest

from syntecxhub_sft import transport as t


def make_pair():
    salt = b"s" * t.SALT_LEN
    c_priv, c_pub = t._keypair()
    s_priv, s_pub = t._keypair()
    client_hello = bytes([t.VERSION]) + c_pub + b"r" * t.RANDOM_LEN
    server_hello = bytes([t.VERSION]) + s_pub + b"r" * t.RANDOM_LEN + salt
    client, t1 = t._derive_session(c_priv, s_pub, client_hello, server_hello, is_client=True)
    server, t2 = t._derive_session(s_priv, c_pub, client_hello, server_hello, is_client=False)
    assert t1 == t2
    return client, server


class SessionTests(unittest.TestCase):
    def test_round_trip(self):
        client, server = make_pair()
        self.assertEqual(server.decrypt(client.encrypt(b"upload begin")), b"upload begin")
        self.assertEqual(client.decrypt(server.encrypt(b"resume info")), b"resume info")

    def test_large_payload_round_trip(self):
        client, server = make_pair()
        blob = bytes(range(256)) * 1000  # 256 KB-ish chunk payload
        self.assertEqual(server.decrypt(client.encrypt(blob)), blob)

    def test_tamper_detected(self):
        client, server = make_pair()
        frame = bytearray(client.encrypt(b"important chunk"))
        frame[-1] ^= 1
        with self.assertRaises(t.TransportError):
            server.decrypt(bytes(frame))

    def test_replay_detected(self):
        client, server = make_pair()
        frame = client.encrypt(b"x")
        server.decrypt(frame)
        with self.assertRaises(t.TransportError):
            server.decrypt(frame)

    def test_nonce_never_repeats(self):
        client, _ = make_pair()
        counters = {client.encrypt(b"x")[: t.COUNTER_LEN] for _ in range(100)}
        self.assertEqual(len(counters), 100)

    def test_derive_psk_is_deterministic_and_salt_dependent(self):
        a = t.derive_psk("hunter2hunter2", b"1" * 16)
        self.assertEqual(a, t.derive_psk("hunter2hunter2", b"1" * 16))
        self.assertNotEqual(a, t.derive_psk("hunter2hunter2", b"2" * 16))

    def test_empty_passphrase_rejected(self):
        with self.assertRaises(t.TransportError):
            t.derive_psk("", b"1" * 16)


if __name__ == "__main__":
    unittest.main()
