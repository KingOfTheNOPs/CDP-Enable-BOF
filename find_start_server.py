#!/usr/bin/env python3
import argparse
import contextlib
import io
import json
import re
import sys
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from pe_signature_finder import analyze_symbols, format_bytes  # type: ignore


def format_c_initializer(data: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in data)


def load_text_section(pe_path: Path):
    pe = pefile.PE(str(pe_path))
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
        if name == ".text":
            return pe, section, section.get_data()
    raise RuntimeError(f"{pe_path} has no .text section")


def verify_unique(pattern: bytes, haystack: bytes) -> int:
    return len(list(re.finditer(re.escape(pattern), haystack)))


def main():
    parser = argparse.ArgumentParser(
        description="Find StartRemoteDebuggingServer and emit a reusable unique signature."
    )
    parser.add_argument("pe", type=Path, help="Path to chrome.dll/msedge.dll")
    parser.add_argument("pdb", type=Path, nargs="?", help="Optional path to matching PDB")
    args = parser.parse_args()

    pe, _text_section, text_data = load_text_section(args.pe)
    output = {
        "binary": str(args.pe),
    }

    if args.pdb:
        with contextlib.redirect_stderr(io.StringIO()):
            results = list(
                analyze_symbols(
                    str(args.pe),
                    str(args.pdb),
                    "*StartRemoteDebuggingServer*",
                    min_sig=8,
                    max_sig=80,
                )
            )
        good = [r for r in results if r.signature and r.match_count == 1]
        if not good:
            raise SystemExit("failed to derive a unique StartRemoteDebuggingServer signature from the PDB")

        result = good[0]
        signature = result.signature
        assert signature is not None
        output["pdb"] = str(args.pdb)
        output["symbol"] = result.symbol.name
        output["signature_rva"] = f"0x{result.symbol.rva:08X}"
        output["signature_va"] = f"0x{pe.OPTIONAL_HEADER.ImageBase + result.symbol.rva:016X}"
        output["signature_length"] = len(signature)
        output["signature_hex"] = format_bytes(signature)
        output["signature_c_initializer"] = format_c_initializer(signature)
        output["copy_to_code"] = (
            "Use this for EDGE_START_SIG if analyzing msedge.dll, or CHROME_START_SIG if analyzing chrome.dll."
        )
        output["text_hits"] = verify_unique(signature, text_data)

    else:
        raise SystemExit("a matching PDB is required")

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
