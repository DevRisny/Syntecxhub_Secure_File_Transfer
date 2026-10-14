import unittest

from syntecxhub_sft import protocol


class ProtocolTests(unittest.TestCase):
    def test_json_round_trip(self):
        kind, message = protocol.decode(protocol.encode_json({"type": "ack", "status": "ok"}))
        self.assertEqual((kind, message), ("json", {"type": "ack", "status": "ok"}))

    def test_chunk_round_trip(self):
        kind, (index, ciphertext) = protocol.decode(protocol.encode_chunk(42, b"ciphertext-bytes"))
        self.assertEqual((kind, index, ciphertext), ("chunk", 42, b"ciphertext-bytes"))

    def test_chunk_index_zero_and_large(self):
        _, (index, _) = protocol.decode(protocol.encode_chunk(0, b"x"))
        self.assertEqual(index, 0)
        _, (index, _) = protocol.decode(protocol.encode_chunk(0xFFFFFFFF, b"x"))
        self.assertEqual(index, 0xFFFFFFFF)

    def test_index_out_of_range_rejected(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.encode_chunk(-1, b"x")
        with self.assertRaises(protocol.ProtocolError):
            protocol.encode_chunk(0x100000000, b"x")

    def test_decode_rejects_garbage(self):
        for bad in (b"", b"X" + b"garbage", b"J" + b"not json", b"J" + b"[]", b"C" + b"ab"):
            with self.assertRaises(protocol.ProtocolError):
                protocol.decode(bad)

    def test_json_must_be_object_with_type(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.decode(protocol.JSON_TAG + b'{"no":"type"}')


if __name__ == "__main__":
    unittest.main()
