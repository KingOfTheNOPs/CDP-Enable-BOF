#!/usr/bin/env python3
import argparse
import json
import re
import struct
import sys
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from pe_signature_finder import PDBParser, demangle_symbol, format_bytes  # type: ignore


# From the current CDP-Enabler project: the Chrome/Edge allocator used for the
# factory object. Wildcards are emitted as "." in the regex.
OPERATOR_NEW_REGEX = (
    rb"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xEB."
    rb"\x48\x8B\xCB\xE8....\x85\xC0\x74.\x48\x8B\xCB"
)
KNOWN_ENTRY1_PATTERNS = {
    "msedge.dll": (
        bytes.fromhex("48 89 D0 0F B7 51 08 48"),
        (1,) * 8,
    ),
    "chrome.dll": (
        bytes.fromhex(
            "41 57 41 56 56 57 55 53 48 81 EC 88 00 00 00 "
            "48 89 D6 48 8B 05 00 00 00 00 "
            "48 31 E0 48 89 84 24 80 00 00 00 "
            "0F B7 59 08 B9 38 00 00 00 E8 00 00 00 00 "
            "48 89 C7 48 8B 05 00 00 00 00 48 8D 0D 00 00 00 00"
        ),
        (
            (1,) * 21 + (0,) * 4 +
            (1,) * 21 + (0,) * 4 +
            (1,) * 6 + (0,) * 4 +
            (1,) * 3 + (0,) * 4
        ),
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


def format_c_mask(mask) -> str:
    return ",".join(str(value) for value in mask)


def compile_masked_pattern(signature: bytes, mask) -> bytes:
    if len(signature) != len(mask):
        raise ValueError("signature and mask lengths differ")
    return b"".join(
        re.escape(bytes((value,))) if fixed else b"."
        for value, fixed in zip(signature, mask)
    )


def load_c_byte_arrays(source: Path):
    text = source.read_text(encoding="utf-8")
    arrays = {}
    for name, body in re.findall(
        r"static\s+const\s+BYTE\s+(\w+)\s*\[\]\s*=\s*\{(.*?)\};",
        text,
        re.S,
    ):
        arrays[name] = bytes(
            int(value.strip(), 0)
            for value in body.split(",")
            if value.strip()
        )
    return arrays


def validate_bof_signatures(text_data: bytes, text_rva: int, source: Path):
    arrays = load_c_byte_arrays(source)
    results = {}
    rules = {
        "start": lambda count: count == 1,
        "new": lambda count: count == 1,
        "entry1": lambda count: count == 1,
        "entry0": lambda count: count <= 32,
    }
    for name, valid_count in rules.items():
        signature = arrays.get(name + "_sig")
        if not signature:
            raise RuntimeError(f"{source} has no {name}_sig array")
        mask = arrays.get(name + "_mask", b"\x01" * len(signature))
        if len(mask) != len(signature):
            raise RuntimeError(f"{name} signature and mask lengths differ")
        matches = [
            match.start()
            for match in re.finditer(
                compile_masked_pattern(signature, mask),
                text_data,
                re.S,
            )
        ]
        results[name] = {
            "valid": valid_count(len(matches)),
            "matches": len(matches),
            "rvas": [f"0x{text_rva + match:08X}" for match in matches],
        }
    return results


def compare_build_signatures(new_pe: Path, old_pe: Path, old_rva: int,
                             new_rva: int, length: int):
    old_bytes = pefile.PE(str(old_pe)).get_data(old_rva, length)
    new_bytes = pefile.PE(str(new_pe)).get_data(new_rva, length)
    if len(old_bytes) != length or len(new_bytes) != length:
        raise RuntimeError("comparison range is outside one of the PE images")
    mask = tuple(int(left == right) for left, right in zip(old_bytes, new_bytes))
    return {
        "signature_c_initializer": format_c_initializer(old_bytes),
        "signature_mask_c_initializer": format_c_mask(mask),
        "stable_bytes": sum(mask),
        "length": length,
        "note": "Mask control-flow and RIP-relative fields, then validate the candidate across all available builds.",
    }


def masked_match_at(data: bytes, offset: int, signature: bytes, mask) -> bool:
    if offset < 0 or offset + len(signature) > len(data):
        return False
    return all(not fixed or data[offset + i] == value for i, (value, fixed) in enumerate(zip(signature, mask)))


def find_minimum_unique_signature(data: bytes, offset: int, min_length=8, max_length=64):
    if offset < 0 or offset + min_length > len(data):
        raise RuntimeError("PDB symbol RVA is outside .text")
    max_length = min(max_length, len(data) - offset)
    for length in range(min_length, max_length + 1):
        signature = data[offset : offset + length]
        first = data.find(signature)
        if first == offset and data.find(signature, first + 1) == -1:
            return signature
    raise RuntimeError(f"failed to derive a unique signature within {max_length} bytes")


def choose_internal_symbols(pe, pdb_path: Path):
    parser = PDBParser(str(pdb_path), pe)
    operator_new = [sym for sym in parser.symbols if sym.name == "??2@YAPEAX_K@Z"]
    entry1 = [
        sym for sym in parser.symbols
        if sym.name.startswith("?CreateForHttpServer@TCPServerSocketFactory@")
    ]
    if len(operator_new) != 1:
        raise RuntimeError(f"expected one operator new symbol in the PDB, got {len(operator_new)}")
    if len(entry1) != 1:
        raise RuntimeError(
            "expected one TCPServerSocketFactory::CreateForHttpServer symbol "
            f"in the PDB, got {len(entry1)}"
        )
    return operator_new[0], entry1[0]


def find_vtable_candidates(rdata_data: bytes, rdata_rva: int, entry1_va: int, image_base: int,
                           text_rva: int, text_size: int, entry0_vas=None):
    candidates = []
    needle = struct.pack("<Q", entry1_va)
    offset = rdata_data.find(needle)
    while offset != -1:
        if offset >= 8 and offset % 8 == 0:
            q0 = struct.unpack_from("<Q", rdata_data, offset - 8)[0]
            if ((entry0_vas is not None and q0 in entry0_vas) or
                (entry0_vas is None and
                 image_base + text_rva <= q0 < image_base + text_rva + text_size)):
                candidates.append(rdata_rva + offset)
        offset = rdata_data.find(needle, offset + 1)
    return candidates


def main():
    parser = argparse.ArgumentParser(
        description="Find the inputs needed to eventually call StartRemoteDebuggingServer."
    )
    parser.add_argument("pe", type=Path, help="Path to chrome.dll/msedge.dll")
    parser.add_argument("pdb", type=Path, nargs="?", help="Optional path to matching PDB")
    parser.add_argument(
        "--validate-bof-signatures",
        type=Path,
        nargs="?",
        const=ROOT / "cdp_enable_iso_bof.c",
        help="also validate every masked signature embedded in the isolation BOF",
    )
    parser.add_argument(
        "--diff-mask",
        nargs=4,
        metavar=("OLD_DLL", "OLD_RVA", "NEW_RVA", "LENGTH"),
        help="emit a candidate masked signature by comparing two Chrome builds",
    )
    args = parser.parse_args()

    if args.diff_mask:
        old_dll, old_rva, new_rva, length = args.diff_mask
        print(json.dumps(compare_build_signatures(
            args.pe,
            Path(old_dll),
            int(old_rva, 0),
            int(new_rva, 0),
            int(length, 0),
        ), indent=2))
        return

    pe = pefile.PE(str(args.pe))
    image_base = pe.OPTIONAL_HEADER.ImageBase
    text_section, text_data = get_section(pe, ".text")
    rdata_section, rdata_data = get_section(pe, ".rdata")

    known_entry1 = KNOWN_ENTRY1_PATTERNS.get(args.pe.name.lower())

    if args.pdb:
        operator_new_symbol, entry1_symbol = choose_internal_symbols(pe, args.pdb)
        operator_new_rva = operator_new_symbol.rva
        operator_new_off = operator_new_rva - text_section.VirtualAddress
        operator_new_sig = find_minimum_unique_signature(text_data, operator_new_off)
        operator_new_mask = (1,) * len(operator_new_sig)

        entry1_rva = entry1_symbol.rva
        entry1_off = entry1_rva - text_section.VirtualAddress
        if known_entry1 and masked_match_at(text_data, entry1_off, *known_entry1):
            entry1_sig, entry1_mask = known_entry1
            entry1_signature_source = "PDB RVA with reusable masked layout"
        else:
            entry1_sig = find_minimum_unique_signature(text_data, entry1_off)
            entry1_mask = (1,) * len(entry1_sig)
            entry1_signature_source = "PDB RVA with exact unique signature"
    else:
        operator_new_off = find_unique_regex(OPERATOR_NEW_REGEX, text_data)
        operator_new_rva = text_section.VirtualAddress + operator_new_off
        operator_new_sig = text_data[operator_new_off : operator_new_off + 26]
        operator_new_mask = (
            (1,) * 10 + (0,) + (1,) * 4 + (0,) * 4 +
            (1,) * 3 + (0,) + (1,) * 3
        )

        if known_entry1 is None:
            raise RuntimeError(f"no built-in CreateForHttpServer signature for {args.pe.name}")
        entry1_sig, entry1_mask = known_entry1
        entry1_off = find_unique_regex(compile_masked_pattern(entry1_sig, entry1_mask), text_data)
        entry1_rva = text_section.VirtualAddress + entry1_off
        entry1_signature_source = "built-in masked fallback"

    operator_new_sig = bytes(
        value if fixed else 0
        for value, fixed in zip(operator_new_sig, operator_new_mask)
    )
    entry1_va = image_base + entry1_rva
    vtable_candidates = find_vtable_candidates(
        rdata_data,
        rdata_section.VirtualAddress,
        entry1_va,
        image_base,
        text_section.VirtualAddress,
        text_section.Misc_VirtualSize,
    )

    if not vtable_candidates:
        raise RuntimeError("failed to derive TCPServerSocketFactory vtable from .rdata")

    vtable_entry1_rva = vtable_candidates[0]

    output = {
        "binary": str(args.pe),
        "operator_new": {
            "rva": f"0x{operator_new_rva:08X}",
            "va": f"0x{image_base + operator_new_rva:016X}",
            "signature": format_bytes(operator_new_sig),
            "signature_c_initializer": format_c_initializer(operator_new_sig),
            "signature_mask_c_initializer": format_c_mask(operator_new_mask),
            "copy_to_code": "replace OPERATOR_NEW_SIG and OPERATOR_NEW_MASK together",
        },
        "tcp_server_socket_factory": {
            "create_for_http_server": {
                "rva": f"0x{entry1_rva:08X}",
                "va": f"0x{entry1_va:016X}",
                "signature_length": len(entry1_sig),
                "signature_hex": format_bytes(entry1_sig),
                "signature_c_initializer": format_c_initializer(entry1_sig),
                "signature_mask_c_initializer": format_c_mask(entry1_mask),
                "signature_source": entry1_signature_source,
                "copy_to_code": "replace EDGE_ENTRY1_SIG and EDGE_ENTRY1_MASK together" if args.pe.name.lower() == "msedge.dll" else "replace CHROME_ENTRY1_SIG and CHROME_ENTRY1_MASK together",
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
        output["pdb"] = str(args.pdb)
        output["operator_new"]["symbol"] = operator_new_symbol.name
        output["tcp_server_socket_factory"]["create_for_http_server"]["symbol"] = demangle_symbol(entry1_symbol.name)
        output["tcp_server_socket_factory"]["create_for_http_server"]["pdb_rva"] = f"0x{entry1_symbol.rva:08X}"
        output["tcp_server_socket_factory"]["create_for_http_server"]["pdb_vtable_refs"] = [
            f"0x{ref:08X}" for ref in vtable_candidates
        ]
        output["tcp_server_socket_factory"]["create_for_http_server"]["signature_matches_pdb_rva"] = True

    validation_failed = False
    if args.validate_bof_signatures:
        validation = validate_bof_signatures(
            text_data,
            text_section.VirtualAddress,
            args.validate_bof_signatures,
        )
        if validation["entry1"]["matches"] == 1:
            validated_entry1_va = image_base + int(validation["entry1"]["rvas"][0], 16)
            entry0_vas = {
                image_base + int(rva, 16)
                for rva in validation["entry0"]["rvas"]
            }
            validated_vtables = find_vtable_candidates(
                rdata_data,
                rdata_section.VirtualAddress,
                validated_entry1_va,
                image_base,
                text_section.VirtualAddress,
                text_section.Misc_VirtualSize,
                entry0_vas or None,
            )
        else:
            validated_vtables = []
        validation["vtable"] = {
            "valid": len(validated_vtables) == 1,
            "matches": len(validated_vtables),
            "rvas": [f"0x{candidate - 8:08X}" for candidate in validated_vtables],
        }
        output["bof_signature_validation"] = validation
        validation_failed = any(not result["valid"] for result in validation.values())

    print(json.dumps(output, indent=2))
    if validation_failed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
