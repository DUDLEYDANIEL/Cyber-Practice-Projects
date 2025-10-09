# Process Creation and Shell Injection – Windows (Python & ctypes)

## Overview

This project demonstrates advanced process injection techniques using Python with the ctypes library to interface directly with the Windows API. The script performs code injection by creating a suspended process, allocating memory within it, writing shellcode, changing memory permissions, and finally executing the injected payload using both remote threading and APC (Asynchronous Procedure Call) mechanisms. This method is foundational in red teaming, malware research, and exploit development.

---

## Core Functionalities

- **Create a Hidden Suspended Process:** Spawns a target process (`notepad.exe`) in a suspended and optionally hidden state for code injection.
- **Allocate Memory in Target Process:** Uses Windows APIs to reserve and commit memory inside the newly created process.
- **Inject Shellcode:** Writes attacker-controlled machine code (msfvenom-generated shellcode) into remote memory.
- **Modify Memory Protections:** Changes the permissions on the memory block to enable execution.
- **Trigger Code Execution:** Executes the injected shellcode using APC (for stealth) and by resuming the remote process's thread.
- **All in Python:** Achieves full process injection using Python’s ctypes for low-level Windows API access.

---

## APIs Utilized

| API / Structure            | Description                                                                                      |
|---------------------------|--------------------------------------------------------------------------------------------------|
| `CreateProcessA`           | Starts a process in a suspended, hidden state with custom settings.                      |
| `VirtualAllocEx`           | Allocates memory within another process’s address space.                                 |
| `WriteProcessMemory`       | Writes arbitrary data (shellcode) into remote memory.                                    |
| `VirtualProtectEx`         | Changes permissions on allocated memory (e.g., to executable).                           |
| `CreateRemoteThread`       | (Alternative, commented out) Directly executes remote code via new thread.               |
| `QueueUserAPC`             | Schedules shellcode for execution in the context of the remote thread (APC).             |
| `ResumeThread`             | Resumes the target process’s primary thread, triggering code execution.                  |
| `STARTUPINFO`              | Configures process window/console settings.                                              |
| `PROCESS_INFORMATION`      | Receives handles and IDs for the spawned process/thread.                                 |
| `SECURITY_ATTRIBUTES`      | Security parameters for process/thread handle inheritance.                               |

---

## Step-by-Step Process

### 1. Spawn a Hidden, Suspended Process

- Calls `CreateProcessA()` to launch notepad.exe, hidden and frozen.
- 
### 2. Allocate Memory

- Uses `VirtualAllocEx()` to open a space in that process’s memory.

### 3. Inject Shellcode

- Writes the shellcode into this pocket with `WriteProcessMemory()`.

### 4. Change Memory Protections

- Modifies the pocket's setting from ‘just storage’ to ‘runnable code’ using `VirtualProtectEx()`.

### 5. Trigger Execution

- **Via APC (`QueueUserAPC`)**: Queues the shellcode as an asynchronous call for the target thread to execute when resumed.

### 6. Resume the Thread

- Uses `ResumeThread()` to let the process's main thread continue—causing the shellcode to be executed via the queued APC.

---

## Security Implications


- **Offensive Use:** A classic technique for process injection, which is frequently used by advanced malware, pentesters, and offensive security tools.
- **Defensive Insight:** Recognizing these API patterns is crucial for defenders and EDR authors to catch and disrupt suspicious activity.

