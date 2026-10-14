import tempfile
import unittest

from syntecxhub_sft.storage import Storage, StorageError, safe_name


def manifest(filename="file.txt", salt="c2FsdA==", hmac="aG1hYw==", chunk_count=3):
    return {
        "filename": filename,
        "size": 300,
        "chunk_size": 100,
        "chunk_count": chunk_count,
        "salt": salt,
        "hmac": hmac,
    }


class SafeNameTests(unittest.TestCase):
    def test_valid_names_pass(self):
        for name in ("report.pdf", "my file (1).txt", "data_2026.csv"):
            self.assertEqual(safe_name(name), name)

    def test_path_traversal_rejected(self):
        for bad in ("../secret", "a/../../etc/passwd", "../../x", "..", ""):
            with self.assertRaises(StorageError):
                safe_name(bad)

    def test_absolute_path_rejected(self):
        with self.assertRaises(StorageError):
            safe_name("/etc/passwd")


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.storage = Storage(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_fresh_upload_starts_at_zero(self):
        self.assertEqual(self.storage.begin_upload(manifest()), 0)

    def test_full_upload_round_trip(self):
        m = manifest()
        self.storage.begin_upload(m)
        for i, payload in enumerate([b"aaa", b"bbb", b"ccc"]):
            self.storage.store_chunk("file.txt", i, payload)
        self.storage.finalize_upload("file.txt", 3)
        stored = list(self.storage.iter_chunks("file.txt", 3))
        self.assertEqual([p for _, p in stored], [b"aaa", b"bbb", b"ccc"])
        self.assertEqual(self.storage.get_manifest("file.txt")["filename"], "file.txt")

    def test_resume_returns_existing_chunk_count(self):
        m = manifest()
        self.storage.begin_upload(m)
        self.storage.store_chunk("file.txt", 0, b"aaa")
        self.storage.store_chunk("file.txt", 1, b"bbb")
        # simulate a fresh client reconnecting with the SAME manifest (same salt/hmac)
        next_index = self.storage.begin_upload(m)
        self.assertEqual(next_index, 2)

    def test_resume_with_mismatched_manifest_refused(self):
        self.storage.begin_upload(manifest(hmac="aG1hYw=="))
        with self.assertRaises(StorageError):
            self.storage.begin_upload(manifest(hmac="ZGlmZmVyZW50"))

    def test_finalize_fails_if_chunks_missing(self):
        self.storage.begin_upload(manifest())
        self.storage.store_chunk("file.txt", 0, b"aaa")
        with self.assertRaises(StorageError):
            self.storage.finalize_upload("file.txt", 3)

    def test_cannot_reupload_completed_file(self):
        m = manifest()
        self.storage.begin_upload(m)
        for i, payload in enumerate([b"aaa", b"bbb", b"ccc"]):
            self.storage.store_chunk("file.txt", i, payload)
        self.storage.finalize_upload("file.txt", 3)
        with self.assertRaises(StorageError):
            self.storage.begin_upload(m)

    def test_download_missing_file_raises(self):
        with self.assertRaises(StorageError):
            self.storage.get_manifest("nope.txt")

    def test_list_only_shows_completed_uploads(self):
        self.storage.begin_upload(manifest(filename="partial.txt"))  # never finalized
        m2 = manifest(filename="done.txt")
        self.storage.begin_upload(m2)
        for i, payload in enumerate([b"a", b"b", b"c"]):
            self.storage.store_chunk("done.txt", i, payload)
        self.storage.finalize_upload("done.txt", 3)
        names = {f["filename"] for f in self.storage.list_files()}
        self.assertEqual(names, {"done.txt"})

    def test_delete_removes_file(self):
        m = manifest()
        self.storage.begin_upload(m)
        for i, payload in enumerate([b"a", b"b", b"c"]):
            self.storage.store_chunk("file.txt", i, payload)
        self.storage.finalize_upload("file.txt", 3)
        self.storage.delete("file.txt")
        with self.assertRaises(StorageError):
            self.storage.get_manifest("file.txt")

    def test_chunk_write_is_idempotent(self):
        self.storage.begin_upload(manifest())
        self.storage.store_chunk("file.txt", 0, b"aaa")
        self.storage.store_chunk("file.txt", 0, b"aaa")  # resumed client resends same chunk
        self.assertEqual(self.storage.next_expected_index("file.txt"), 1)


if __name__ == "__main__":
    unittest.main()
