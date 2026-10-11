"""ELF/PE upload validation and non-executing imported-symbol triage."""
import io
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.binary_analyzer import (
    _bounded_disassembly,
    _call_sites,
    analyze_binary,
    inspect_binary,
)


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
        with (
            patch("app.services.binary_analyzer.subprocess.run", side_effect=[
                CompletedProcess([], 0, "NEEDED libdemo.so\n", ""),
                CompletedProcess([], 0, "0000 DF *UND* 0000 strcpy@GLIBC_2.2.5\n0000 DF *UND* 0000 recv@GLIBC_2.2.5\n", ""),
                CompletedProcess([], 0, "00000000 g F .text 00000010 parse_packet\n", ""),
            ]) as run,
            patch("app.services.binary_analyzer._bounded_disassembly", return_value=(
                "00000000 <parse_packet>:\n   12: call 30 <strcpy@plt>\n", False,
            )),
        ):
            result = analyze_binary(path, ["buffer_overflow"])
        self.assertEqual(result["libraries"], ["libdemo.so"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["vuln_type"], "buffer_overflow")
        self.assertIn("尚未证明漏洞存在", result["findings"][0]["trigger_cond"])
        self.assertEqual(result["named_functions"], ["parse_packet"])
        self.assertEqual(result["external_input_apis"], ["recv"])
        self.assertEqual(result["call_sites"], [{"address": "0x12", "caller": "parse_packet", "symbol": "strcpy"}])
        self.assertIn("parse_packet@0x12", result["findings"][0]["code_context"])
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
        ]), patch("app.services.binary_analyzer._bounded_disassembly", return_value=("", False)):
            result = analyze_binary(path, ["buffer_overflow"])
        self.assertEqual(result["libraries"], ["KERNEL32.dll"])
        self.assertEqual(result["named_functions"], [])
        self.assertEqual(result["external_input_apis"], ["recv"])
        self.assertEqual(len(result["findings"]), 1)

    def test_call_sites_include_pe_import_thunks_but_skip_unwatched_calls(self):
        disassembly = """00000001400014d0 <parse_packet>:
  1400014fc: call 140001f50 <strcpy>
  140001502: call 140001f60 <helper>
  140001508: call 140001f70 <__imp_recv>
"""
        self.assertEqual(_call_sites(disassembly), [
            {"address": "0x1400014fc", "caller": "parse_packet", "symbol": "strcpy"},
            {"address": "0x140001508", "caller": "parse_packet", "symbol": "recv"},
        ])

    def test_disassembly_output_is_bounded(self):
        class Process:
            def __init__(self):
                self.stdout = io.BytesIO(b"0123456789")
                self.returncode = None

            def poll(self):
                return self.returncode

            def kill(self):
                self.returncode = -9

            def wait(self, timeout):
                self.returncode = self.returncode or 0
                return self.returncode

        process = Process()
        with patch("app.services.binary_analyzer.subprocess.Popen", return_value=process):
            output, truncated = _bounded_disassembly(Path("dummy"), limit=5)
        self.assertEqual(output, "01234")
        self.assertTrue(truncated)
        self.assertEqual(process.returncode, -9)


if __name__ == "__main__":
    unittest.main()
