#!/usr/bin/env python3
import argparse
import contextlib
import io
import json
import re
import struct
import sys
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from pe_signature_finder import analyze_symbols, demangle_symbol, format_bytes  # type: ignore


# From the current CDP-Enabler project: the Chrome/Edge allocator used for the
# factory object. Wildcards are emitted as "." in the regex.
OPERATOR_NEW_REGEX = (
    rb"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xEB."
    rb"\x48\x8B\xCB\xE8....\x85\xC0\x74.\x48\x8B\xCB"
)
OPERATOR_NEW_SIGNATURE = "40 53 48 83 EC 20 48 8B D9 EB ?? 48 8B CB E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B CB"

KNOWN_ENTRY1_SIGNATURES = {
    "msedge.dll": bytes.fromhex("48 89 D0 0F B7 51 08 48"),
    "chrome.dll": bytes.fromhex(
        "41 57 41 56 56 57 55 53 48 81 EC 88 00 00 00 48 89 D6 48 8B 05 07"
    ),
}


def get_section(pe, section_name: str):
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
        if name == section_name:
            return section, section.get_data()
    raise RuntimeError(f"{pe.filename} has no {section_name} section")


def find_unique_regex(pattern: bytes, data: bytes) -> int:
    matches = [m.start() for m in re.finditer(pattern, data, re.S)]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one match, got {len(matches)}")
    return matches[0]


def format_c_initializer(data: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in data)


def choose_tcp_factory_entry1(pe_path: Path, pdb_path: Path):
    with contextlib.redirect_stderr(io.StringIO()):
        results = list(
            analyze_symbols(
                str(pe_path),
                str(pdb_path),
                "*CreateForHttpServer*",
                min_sig=8,
                max_sig=64,
            )
        )

    for result in results:
        demangled = demangle_symbol(result.symbol.name)
        if "TCPServerSocketFactory::CreateForHttpServer()" in demangled:
            return result, demangled

    raise RuntimeError("TCPServerSocketFactory::CreateForHttpServer was not found in the PDB")


def main():
    parser = argparse.ArgumentParser(
        description="Find the inputs needed to eventually call StartRemoteDebuggingServer."
    )
    parser.add_argument("pe", type=Path, help="Path to chrome.dll/msedge.dll")
    parser.add_argument("pdb", type=Path, nargs="?", help="Optional path to matching PDB")
    args = parser.parse_args()

    pe = pefile.PE(str(args.pe))
    image_base = pe.OPTIONAL_HEADER.ImageBase
    text_section, text_data = get_section(pe, ".text")
    rdata_section, rdata_data = get_section(pe, ".rdata")

    operator_new_off = find_unique_regex(OPERATOR_NEW_REGEX, text_data)
    operator_new_rva = text_section.VirtualAddress + operator_new_off

    entry1_sig = KNOWN_ENTRY1_SIGNATURES.get(args.pe.name.lower())
    if entry1_sig is None:
        raise RuntimeError(f"no built-in CreateForHttpServer signature for {args.pe.name}")

    entry1_off = find_unique_regex(re.escape(entry1_sig), text_data)
    entry1_sig_rva = text_section.VirtualAddress + entry1_off
    entry1_rva = entry1_sig_rva
    entry1_va = image_base + entry1_rva
    vtable_candidates = []

    for offset in range(0, len(rdata_data) - 16 + 1, 8):
        q0, q1 = struct.unpack_from("<QQ", rdata_data, offset)
        if (
            q1 == entry1_va
            and image_base + text_section.VirtualAddress
            <= q0
            < image_base + text_section.VirtualAddress + text_section.Misc_VirtualSize
        ):
            vtable_candidates.append(rdata_section.VirtualAddress + offset)

    if not vtable_candidates:
        raise RuntimeError("failed to derive TCPServerSocketFactory vtable from .rdata")

    vtable_entry1_rva = vtable_candidates[0]

    output = {
        "binary": str(args.pe),
        "operator_new": {
            "rva": f"0x{operator_new_rva:08X}",
            "va": f"0x{image_base + operator_new_rva:016X}",
            "signature": OPERATOR_NEW_SIGNATURE,
            "copy_to_code": "OPERATOR_NEW_SIG",
        },
        "tcp_server_socket_factory": {
            "create_for_http_server": {
                "rva": f"0x{entry1_rva:08X}",
                "va": f"0x{entry1_va:016X}",
                "signature_hex": format_bytes(entry1_sig),
                "signature_c_initializer": format_c_initializer(entry1_sig),
                "copy_to_code": "EDGE_ENTRY1_SIG" if args.pe.name.lower() == "msedge.dll" else "CHROME_ENTRY1_SIG",
                "derived_vtable_entry1_candidates": [f"0x{candidate:08X}" for candidate in vtable_candidates],
                "vtable_entry1_rva": f"0x{vtable_entry1_rva:08X}",
                "vtable_rva": f"0x{vtable_entry1_rva - 8:08X}",
                "vtable_va": f"0x{image_base + vtable_entry1_rva - 8:016X}",
                "note": "The script emits the CreateForHttpServer function signature and derives the vtable location. The PIC code still uses VTABLE_ENTRY0_SIG / VTABLE_ENTRY0_MASK for vtable matching if that helper drifts.",
            },
            "layout": {
                "size": 16,
                "vtable_offset": 0,
                "port_offset": 8,
            },
        },
        "filepath": {
            "size": 24,
            "initialization": "all-zero empty FilePath blob",
        },
        "call_shape": {
            "rcx": "pointer to unique_ptr<DevToolsSocketFactory> wrapper",
            "rdx": "empty base::FilePath for active_port_output_directory",
            "r8": "empty base::FilePath for debug_frontend_dir",
            "r9d": "RemoteDebuggingServerMode",
        },
    }

    if args.pdb:
        entry1_result, entry1_demangled = choose_tcp_factory_entry1(args.pe, args.pdb)
        output["pdb"] = str(args.pdb)
        output["tcp_server_socket_factory"]["create_for_http_server"]["symbol"] = entry1_demangled
        output["tcp_server_socket_factory"]["create_for_http_server"]["pdb_rva"] = f"0x{entry1_result.symbol.rva:08X}"
        output["tcp_server_socket_factory"]["create_for_http_server"]["pdb_vtable_refs"] = [
            f"0x{ref:08X}" for ref in entry1_result.vtable_refs
        ]
        output["tcp_server_socket_factory"]["create_for_http_server"]["signature_matches_pdb_rva"] = (
            entry1_sig_rva == entry1_result.symbol.rva
        )

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
