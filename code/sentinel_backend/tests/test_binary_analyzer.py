"""ELF/PE upload validation and non-executing imported-symbol triage."""
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.binary_analyzer import analyze_binary, inspect_binary


class BinaryAnalyzerTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[3] / "tmp"
        scratch.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_elf_shared_header(self):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 16, 3)
        path = self.root / "libdemo.so"
        path.write_bytes(header)
        self.assertEqual(inspect_binary(path), {"format": "ELF", "bits": 64, "kind": "shared"})

    def test_pe_executable_header_with_offset_beyond_first_page(self):
        header = bytearray(8192)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 4096)
        header[4096:4100] = b"PE\0\0"
        struct.pack_into("<H", header, 4096 + 24, 0x20B)
        path = self.root / "demo.exe"
        path.write_bytes(header)
        self.assertEqual(inspect_binary(path), {"format": "PE", "bits": 64, "kind": "executable"})

    def test_rejects_renamed_non_binary(self):
        path = self.root / "fake.exe"
        path.write_bytes(b"not a PE file")
        with self.assertRaisesRegex(ValueError, "不是 ELF 或 PE"):
            inspect_binary(path)

    def test_imported_api_is_only_unverified_candidate(self):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 16, 2)
        path = self.root / "demo.elf"
        path.write_bytes(header)
        from subprocess import CompletedProcess
        with patch("app.services.binary_analyzer.subprocess.run", side_effect=[
            CompletedProcess([], 0, "NEEDED libdemo.so\n", ""),
            CompletedProcess([], 0, "0000 DF *UND* 0000 strcpy@GLIBC_2.2.5\n0000 DF *UND* 0000 recv@GLIBC_2.2.5\n", ""),
            CompletedProcess([], 0, "00000000 g F .text 00000010 parse_packet\n", ""),
        ]) as run:
            result = analyze_binary(path, ["buffer_overflow"])
        self.assertEqual(result["libraries"], ["libdemo.so"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["vuln_type"], "buffer_overflow")
        self.assertIn("尚未证明漏洞存在", result["findings"][0]["trigger_cond"])
        self.assertEqual(result["named_functions"], ["parse_packet"])
        self.assertEqual(result["external_input_apis"], ["recv"])
        self.assertEqual([call.args[0][1] for call in run.call_args_list], ["-p", "-T", "-t"])

    def test_pe_imports_without_named_functions_remain_static(self):
        header = bytearray(128)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 64)
        header[64:68] = b"PE\0\0"
        struct.pack_into("<H", header, 64 + 24, 0x10B)
        path = self.root / "demo.exe"
        path.write_bytes(header)
        from subprocess import CompletedProcess
        with patch("app.services.binary_analyzer.subprocess.run", side_effect=[
            CompletedProcess([], 0, "DLL Name: KERNEL32.dll\nrecv\nstrcpy\n", ""),
            CompletedProcess([], 1, "", "no dynamic symbols"),
            CompletedProcess([], 0, "SYMBOL TABLE:\nno symbols\n", ""),
        ]):
            result = analyze_binary(path, ["buffer_overflow"])
        self.assertEqual(result["libraries"], ["KERNEL32.dll"])
        self.assertEqual(result["named_functions"], [])
        self.assertEqual(result["external_input_apis"], ["recv"])
        self.assertEqual(len(result["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
