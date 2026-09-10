# Technical Analysis: Ardamax Keylogger Dropper (Unpacked)

## 📌 Overview
This repository contains a detailed reverse engineering analysis of the **Ardamax Keylogger** lightweight dropper (32-bit, Windows User-mode). 
The analysis focuses on exploring the self-extracting mechanics, custom overlay processing, and dynamic payload execution without relying on automated sandboxes.

---

## 📊 Binary Specifications
* **File Name:** ArdamaxKeylogger.exe
* **Architecture:** x86 (32-bit Execution)
* **Executable Format:** Portable Executable (PE)
* **Subsystem:** Windows GUI (`__set_app_type(2)`)
* **Base Address (ImageBase):** `0x00400000`
* **Static Size on Disk:** ~783 KB
* **PE Header Declared Size:** 19,040 Bytes (approx. 18.5 KB)
* **Overlay Size:** ~764 KB (Encrypted payload appended to the end of the PE structure)

---

## 🔍 Execution Flow & Core Logic

### 1. Runtime Initialization (`entry`)
The binary utilizes a standard Microsoft Visual C++ CRT startup routine. It configures Structured Exception Handling (SEH) via the `FS` register (`FS:`) to suppress runtime crashes and silently terminate upon exceptions. 
After parsing command-line arguments via `__getmainargs`, it resolves the module handle and passes execution to the primary main dispatcher at `FUN_0040141e`.

### 2. Payload Extraction Sequence (`FUN_004010be`)
The main dispatcher initializes a 520-byte wide-char buffer and calls `GetTempPathW` to pinpoint the current user's volatile storage (`%\AppData\Local\Temp\`). 

Execution then shifts to `FUN_004010be`, which handles raw file I/O operations:
1. **Self-Opening:** Resolves its own disk path via `GetModuleFileNameW` and calls `CreateFileW` with `GENERIC_READ` (`0x80000000`) and `FILE_SHARE_READ` (`1`) flags.
2. **Signature Verification:** Moves the file pointer 28 bytes inward (`0x1c`) using `SetFilePointer`. It verifies the custom SFX packing signature against the hardcoded hex value **`0x46587253`** (ASCII: `SFXr` / `SrXF`).
3. **Dropping Mechanism:** Upon validation, the dropper seeks into the overlay data. It leverages `GetTempFileNameW` with a custom prefix (`L"@"`) to generate unique pseudo-random filenames inside the `Temp` folder.
4. **Decompression:** It spins up two parallel extraction cycles, creating files via `CreateFileW` with `GENERIC_WRITE` (`0x40000000`) and `CREATE_ALWAYS` (`5`). It unpacks the raw payload (malicious `.dll` and helper `.exe` files) into the Temp directory.
5. **Resource Cleanup:** Calls `CloseHandle` on all native handles to prevent file-locking locks.

### 3. Dynamic Execution Phase (`FUN_00401000`)
Rather than starting a visible subprocess, the loader switches to dynamic library loading to evade trivial endpoint detection:
```c
hModule = LoadLibraryW(extracted_dll_path);
pFVar1 = GetProcAddress(hModule, "sfx_main");
```
It maps the dropped DLL into its own virtual memory space, resolves the unexported execution symbol **`sfx_main`**, and jumps directly to its pointer, completely shifting execution control to the main core of the Ardamax Keylogger.

---

## 🛡️ Defending & Detection Strategies (Anti-Malware Perspective)

Based on this analysis, the malware can be successfully stopped by deploying the following rules in a host intrusion prevention system (HIPS) or a kernel-mode filtering driver (like File System Minifilter):

1. **Path-Based Behavioral Blocking:** Monitor `GetTempFileNameW` / `CreateFileW` sequences. Any process attempting to create executable modules (`.exe`, `.dll`) within the user's localized `%TEMP%` zone should be immediately denied with `STATUS_ACCESS_DENIED`.
2. **Overlay Inspection:** Enforce strict inspection on PE structures where `Static_Size_On_Disk >> Declared_PE_Size`.
3. **Dynamic API Monitoring:** Hook `GetProcAddress` to flag user-mode processes attempting to dynamically resolve undocumented/suspicious entry points like `sfx_main` inside newly dropped untrusted modules.
