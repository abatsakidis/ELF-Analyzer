# ELF Analyzer

A powerful ELF binary analysis tool for Linux penetration testers and reverse engineers.  
Supports extraction of security features, ROP gadget search, symbol resolution, disassembly, and integration with external tools like `angr`, `radare2`, and `Ghidra`.

---

## 🔧 Features

- Detects:
  - PIE (Position Independent Executable)
  - NX (Non-Executable Stack)
  - RELRO (Partial/Full)
  - Stack Canary presence
- Lists dynamic imports and symbols
- Disassembles `.text` section using Capstone
- Finds basic ROP gadgets
- Exports results to JSON
- Optional integration with:
  - `angr` (symbolic execution)
  - `radare2` (function & string info)
  - `Ghidra` (headless scripting)
- Supports summary, verbose and quiet modes

---

## 📦 Requirements

- Python 3.6+
- Modules:
  - `pyelftools`
  - `capstone`
  - `angr` (optional)
  - `r2pipe` (optional)

Install dependencies:

```bash
pip install pyelftools capstone angr r2pipe
```

## 🚀 Usage

python3 analyzer.py <elf_file> [options]

### Options:
Option	Description
--json-output FILE	Save results to JSON file
--verbose	Print detailed results to stdout
--summary	Print one-line summary of key features
--quiet	Suppress all output (for scripting)
--angr	Analyze with angr
--r2	Analyze with radare2
--ghidra	Analyze with Ghidra (headless)
--ghidra-path PATH	Custom path to Ghidra installation

##📄 Example

python3 analyzer.py /bin/ls --summary

python3 analyzer.py ./my_binary --json-output result.json --verbose

python3 analyzer.py ./target --angr --r2 --json-output out.json --quiet

## 📤 Sample Output (Summary)

[SUMMARY] Arch: 64-bit | PIE: Yes | NX: Yes | Canary: Yes | RELRO: Full | Imports: 17 | Symbols: 128

## 📁 Output (JSON format)

{
  "file": "./binary",
  "architecture": "64-bit",
  "pie": true,
  "nx": true,
  "relro": "Full RELRO",
  "canary": true,
  "imports": ["puts", "printf", "exit"],
  "symbols": [
    { "name": "main", "address": "0x401080", "type": "FUNC" },
    ...
  ],
  "rop_gadgets": [
    "0x400123:\tpop rdi ; ret",
    ...
  ],
  "disassembly": [
    "0x401080:\tpush rbp",
    "0x401081:\tmov rbp, rsp",
    ...
  ]
}

## 🛠 Notes

    For --ghidra to work, ensure Ghidra is installed and the analyzeHeadless script is available.

    --quiet disables all terminal output except for errors.

## 📜 License

MIT License
