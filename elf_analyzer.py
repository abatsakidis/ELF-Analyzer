#!/usr/bin/env python3

import os
import json
import argparse
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from capstone import *

try:
    import angr
except ImportError:
    angr = None

try:
    import r2pipe
except ImportError:
    r2pipe = None


def check_nx(elf):
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_GNU_STACK':
            return not bool(segment['p_flags'] & 0x1)
    return False

def check_pie(elf):
    return elf.header['e_type'] == 'ET_DYN'

def check_relro(elf):
    has_gnu_relro = False
    bind_now = False
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_GNU_RELRO':
            has_gnu_relro = True
    for section in elf.iter_sections():
        if section.name == '.dynamic':
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_BIND_NOW':
                    bind_now = True
    if has_gnu_relro and bind_now:
        return "Full RELRO"
    elif has_gnu_relro:
        return "Partial RELRO"
    return "No RELRO"

def check_canary(elf):
    for section in elf.iter_sections():
        if section.name == '.dynsym':
            for sym in section.iter_symbols():
                if '__stack_chk_fail' in sym.name:
                    return True
    return False

def list_imports(elf):
    imports = set()
    for section in elf.iter_sections():
        if section.name == '.dynsym':
            for sym in section.iter_symbols():
                if sym['st_info']['bind'] == 'STB_GLOBAL' and sym['st_shndx'] == 'SHN_UNDEF':
                    imports.add(sym.name)
    return sorted(imports)

def resolve_symbols(elf):
    symbols = []
    for section in elf.iter_sections():
        if section.name in ['.symtab', '.dynsym']:
            for sym in section.iter_symbols():
                symbols.append({
                    "name": sym.name,
                    "address": hex(sym['st_value']),
                    "type": sym['st_info']['type']
                })
    return symbols

def find_rop_gadgets(elf, data, base_addr):
    gadgets = []
    text_section = elf.get_section_by_name('.text')
    if not text_section:
        return gadgets
    text_data = text_section.data()
    addr = text_section['sh_addr']

    arch = elf.get_machine_arch()
    if arch == 'x86':
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == 'x64':
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        return ["Unsupported architecture for ROP"]

    for i in range(len(text_data) - 10):
        for insn in md.disasm(text_data[i:i+10], addr + i):
            if 'ret' in insn.mnemonic or 'pop' in insn.mnemonic or 'leave' in insn.mnemonic:
                gadgets.append(f"{hex(insn.address)}:\t{insn.mnemonic} {insn.op_str}")
    return gadgets

def disassemble_text(elf, limit=20):
    text = elf.get_section_by_name('.text')
    if not text:
        return ["No .text section found"]
    code = text.data()
    addr = text['sh_addr']
    arch = elf.get_machine_arch()

    if arch == 'x86':
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == 'x64':
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        return ["Unsupported architecture"]

    disasm_lines = []
    for i, insn in enumerate(md.disasm(code, addr)):
        if i >= limit:
            break
        disasm_lines.append(f"{hex(insn.address)}:\t{insn.mnemonic} {insn.op_str}")
    return disasm_lines

def analyze_elf(file_path):
    results = {}

    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return {}

    with open(file_path, 'rb') as f:
        elf = ELFFile(f)

        results["file"] = file_path
        results["architecture"] = '64-bit' if elf.elfclass == 64 else '32-bit'
        results["pie"] = check_pie(elf)
        results["nx"] = check_nx(elf)
        results["relro"] = check_relro(elf)
        results["canary"] = check_canary(elf)
        results["imports"] = list_imports(elf)
        results["symbols"] = resolve_symbols(elf)

        f.seek(0)
        raw_data = f.read()
        results["rop_gadgets"] = find_rop_gadgets(elf, raw_data, 0)[:10]
        results["disassembly"] = disassemble_text(elf)

    return results

def save_json(results, output_path):
    try:
        with open(output_path, 'w') as out:
            json.dump(results, out, indent=4)
        print(f"\n[+] Results saved to {output_path}")
    except Exception as e:
        print(f"[!] Failed to save JSON: {e}")

# Optional tools
def analyze_with_angr(path):
    if angr is None:
        print("[-] angr not installed.")
        return
    print("\n[+] angr: Analyzing binary with symbolic execution...")
    proj = angr.Project(path, auto_load_libs=False)
    entry_state = proj.factory.entry_state()
    cfg = proj.analyses.CFGFast()
    print(f"    - Total functions detected: {len(cfg.kb.functions)}")

def analyze_with_r2(path):
    if r2pipe is None:
        print("[-] r2pipe not installed.")
        return
    print("\n[+] radare2: Launching r2 analysis...")
    r2 = r2pipe.open(path)
    r2.cmd('aaa')
    funcs = r2.cmdj('aflj')
    if funcs:
        print(f"    - Found {len(funcs)} functions.")
    strings = r2.cmdj('izj')
    if strings:
        print(f"    - Found {len(strings)} strings.")

def run_ghidra_analysis(path, ghidra_path="/opt/ghidra"):
    print("\n[+] Ghidra: Running headless analysis...")
    project_dir = "/tmp/ghidra_project"
    project_name = "AutoAnalyze"
    script = [
        f"{ghidra_path}/support/analyzeHeadless",
        project_dir,
        project_name,
        "-import", path,
        "-deleteProject",
        "-scriptPath", f"{ghidra_path}/Ghidra/Features/Base/ghidra_scripts",
        "-postScript", "FunctionID.java",
        "-noanalysis"
    ]
    try:
        subprocess.run(script, check=True)
        print("    - Ghidra analysis complete.")
    except Exception as e:
        print(f"    - Ghidra error: {e}")

def generate_summary(results):
    return (
        f"[SUMMARY] Arch: {results.get('architecture')} | "
        f"PIE: {'Yes' if results.get('pie') else 'No'} | "
        f"NX: {'Yes' if results.get('nx') else 'No'} | "
        f"Canary: {'Yes' if results.get('canary') else 'No'} | "
        f"RELRO: {results.get('relro')} | "
        f"Imports: {len(results.get('imports', []))} | "
        f"Symbols: {len(results.get('symbols', []))}"
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ELF Analyzer with export to JSON")
    parser.add_argument("elf_path", help="Path to ELF binary")
    parser.add_argument("--angr", action="store_true", help="Analyze with angr")
    parser.add_argument("--r2", action="store_true", help="Analyze with radare2")
    parser.add_argument("--ghidra", action="store_true", help="Analyze with Ghidra (headless)")
    parser.add_argument("--ghidra-path", help="Path to Ghidra", default="/opt/ghidra")
    parser.add_argument("--json-output", help="Output path for JSON file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", action="store_true", help="Suppress output (for scripting)")
    parser.add_argument("--summary", action="store_true", help="Print a one-line summary of key ELF features")

    args = parser.parse_args()

    # Quiet mode overrides everything
    def log(msg):
        if not args.quiet:
            print(msg)

    results = analyze_elf(args.elf_path)

    if not results:
        log("[!] Analysis failed or file not valid ELF.")
        exit(1)

    if args.json_output:
        save_json(results, args.json_output)

    # Show results only if not quiet and either no json_output or --verbose is enabled
    if not args.quiet:
        if args.summary:
            log("\n" + generate_summary(results))
        elif args.verbose or not args.json_output:
            log("\n[+] ELF Analysis Results:")
            for key, value in results.items():
                log(f"\n== {key.upper()} ==")
                if isinstance(value, list):
                    for item in value:
                        log(f"  - {item}")
                else:
                    log(f"  {value}")

    # Extra analysis tools
    if args.angr:
        analyze_with_angr(args.elf_path)
    if args.r2:
        analyze_with_r2(args.elf_path)
    if args.ghidra:
        run_ghidra_analysis(args.elf_path, args.ghidra_path)

