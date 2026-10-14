import io
import unittest

from syntecxhub_sft.filecrypto import (
    IntegrityError,
    check_file_hmac,
    decrypt_chunk,
    derive_file_keys,
    encrypt_file,
    new_salt,
    whole_file_hmac,
)


class KeyDerivationTests(unittest.TestCase):
    def test_same_passphrase_and_salt_give_same_keys(self):
        salt = new_salt()
        a = derive_file_keys("correct horse", salt)
        b = derive_file_keys("correct horse", salt)
        self.assertEqual(a.aes_key, b.aes_key)
        self.assertEqual(a.hmac_key, b.hmac_key)

    def test_aes_key_and_hmac_key_differ(self):
        keys = derive_file_keys("correct horse", new_salt())
        self.assertNotEqual(keys.aes_key, keys.hmac_key)

    def test_different_salt_gives_different_keys(self):
        a = derive_file_keys("same passphrase", new_salt())
        b = derive_file_keys("same passphrase", new_salt())
        self.assertNotEqual(a.aes_key, b.aes_key)

    def test_different_passphrase_gives_different_keys(self):
        salt = new_salt()
        a = derive_file_keys("passphrase one", salt)
        b = derive_file_keys("passphrase two", salt)
        self.assertNotEqual(a.aes_key, b.aes_key)

    def test_empty_passphrase_rejected(self):
        with self.assertRaises(ValueError):
            derive_file_keys("", new_salt())


class ChunkRoundTripTests(unittest.TestCase):
    def test_round_trip(self):
        keys = derive_file_keys("p", new_salt())
        data = b"hello world, this is a secret document." * 50
        chunks = list(encrypt_file(io.BytesIO(data), keys, chunk_size=100))
        rebuilt = b"".join(decrypt_chunk(keys, i, ct) for i, ct in chunks)
        self.assertEqual(rebuilt, data)

    def test_empty_file_yields_no_chunks(self):
        keys = derive_file_keys("p", new_salt())
        self.assertEqual(list(encrypt_file(io.BytesIO(b""), keys)), [])

    def test_ciphertext_does_not_contain_plaintext(self):
        keys = derive_file_keys("p", new_salt())
        secret = b"TOP SECRET PAYROLL NUMBERS 123456"
        _, ciphertext = next(encrypt_file(io.BytesIO(secret), keys, chunk_size=1024))
        self.assertNotIn(b"TOP SECRET", ciphertext)
        self.assertNotIn(b"123456", ciphertext)

    def test_tampered_chunk_rejected(self):
        keys = derive_file_keys("p", new_salt())
        _, ct = next(encrypt_file(io.BytesIO(b"data"), keys))
        bad = bytearray(ct)
        bad[-1] ^= 1
        with self.assertRaises(IntegrityError):
            decrypt_chunk(keys, 0, bytes(bad))

    def test_chunk_with_wrong_index_rejected(self):
        """Nonce is derived from the index, so index 0's ciphertext must not decrypt as index 1."""
        keys = derive_file_keys("p", new_salt())
        _, ct = next(encrypt_file(io.BytesIO(b"data"), keys))
        with self.assertRaises(IntegrityError):
            decrypt_chunk(keys, 1, ct)

    def test_wrong_key_rejected(self):
        keys_a = derive_file_keys("passphrase-a", new_salt())
        keys_b = derive_file_keys("passphrase-b", new_salt())
        _, ct = next(encrypt_file(io.BytesIO(b"data"), keys_a))
        with self.assertRaises(IntegrityError):
            decrypt_chunk(keys_b, 0, ct)

    def test_many_chunks_each_have_distinct_nonce(self):
        keys = derive_file_keys("p", new_salt())
        data = os_urandom_like(5000)
        chunks = list(encrypt_file(io.BytesIO(data), keys, chunk_size=100))
        self.assertEqual(len(chunks), 50)
        self.assertEqual(len({ct for _, ct in chunks}), 50)


class WholeFileHmacTests(unittest.TestCase):
    def test_matching_file_passes(self):
        keys = derive_file_keys("p", new_salt())
        data = b"a" * 10000
        digest = whole_file_hmac(io.BytesIO(data), keys)
        self.assertEqual(len(digest), 32)

    def test_reordered_or_duplicated_chunks_fail_whole_file_check(self, tmp_write=None):
        import os
        import tempfile

        keys = derive_file_keys("p", new_salt())
        data = b"ABCDEFGH" * 1000
        digest = whole_file_hmac(io.BytesIO(data), keys)

        handle, path = tempfile.mkstemp()
        os.close(handle)
        try:
            with open(path, "wb") as fh:
                fh.write(data[100:] + data[:100])  # chunks swapped
            self.assertFalse(check_file_hmac(digest, keys, path))
            with open(path, "wb") as fh:
                fh.write(data)
            self.assertTrue(check_file_hmac(digest, keys, path))
        finally:
            os.unlink(path)


def os_urandom_like(n: int) -> bytes:
    import os

    return os.urandom(n)


if __name__ == "__main__":
    unittest.main()
