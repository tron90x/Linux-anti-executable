# Linux Anti-Executable

A Linux application that controls executable file execution, similar to Windows "Anti-Executable". It monitors and controls which programs can run on your system by maintaining a whitelist of approved executables.

## Overview

This application consists of two main components:

1. **Daemon (lexec-daemon)** - Runs with root privileges, uses Linux `fanotify` API to intercept execution attempts
2. **GUI Client (lexec-gui)** - User interface for allow/deny prompts and whitelist management

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER SPACE                               │
│                                                                  │
│  ┌──────────────────┐        ┌────────────────────────────────┐ │
│  │   lexec-gui      │◄──────►│        lexec-daemon            │ │
│  │                  │  Unix  │                                │ │
│  │ ┌──────────────┐ │ Socket │  ┌──────────────────────────┐  │ │
│  │ │Allow/Deny   │ │        │  │  Whitelist Database      │  │ │
│  │ │Dialog       │ │        │  │  (SQLite)                │  │ │
│  │ └──────────────┘ │        │  └──────────────────────────┘  │ │
│  │                  │        │                                │ │
│  │ ┌──────────────┐ │        │  ┌──────────────────────────┐  │ │
│  │ │Whitelist    │ │        │  │  fanotify listener       │  │ │
│  │ │Manager      │ │        │  │  (FAN_OPEN_EXEC_PERM)    │  │ │
│  │ └──────────────┘ │        │  └──────────────┬───────────┘  │ │
│  └──────────────────┘        └─────────────────┼──────────────┘ │
│                                                │                 │
├────────────────────────────────────────────────┼─────────────────┤
│                         KERNEL SPACE           │                 │
│                                                ▼                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    fanotify subsystem                        ││
│  │                                                              ││
│  │   Hooks into: execve(), execveat(), open() with O_EXEC      ││
│  │   Returns: FAN_ALLOW or FAN_DENY based on daemon response   ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **First-run scanning**: Catalogs all existing executables and shared libraries
- **Real-time interception**: Blocks unknown executables until user approval
- **Whitelist management**: SQLite database storing approved files by SHA256 hash
- **Hash-based identification**: Files identified by content hash, not just path
- **Shared library monitoring**: Tracks .so files loaded via dlopen() and dynamic linker
- **Persistence**: Approved files remain approved across reboots
- **System protection**: Critical system files auto-whitelisted

## What Gets Intercepted

| File Type | Intercepted | Mechanism |
|-----------|-------------|-----------|
| ELF executables | ✅ Yes | `FAN_OPEN_EXEC_PERM` on execve() |
| Shell scripts (#!/bin/bash) | ✅ Yes | Interpreter (bash) is intercepted |
| Python scripts | ✅ Yes | Interpreter (python) is intercepted |
| Shared libraries (.so) | ✅ Yes | `FAN_OPEN_PERM` filtered by extension |
| Libraries via dlopen() | ✅ Yes | Same FAN_OPEN_PERM mechanism |
| Kernel modules (.ko) | ⚠️ Partial | Requires additional configuration |

### Shared Library (.so) Monitoring Details

The daemon intercepts shared library loading through `FAN_OPEN_PERM`:

```
Program starts → ld-linux.so loads dependencies → Each .so file triggers FAN_OPEN_PERM
                                                            ↓
                                              Daemon checks whitelist → Allow/Deny
```

To minimize performance impact, FAN_OPEN_PERM events are filtered:
1. Only files with `.so` extension or `.so.X.Y.Z` pattern are checked
2. Non-ELF files are immediately allowed
3. Whitelisted files return instantly (hash lookup)

## Technical Requirements

- Linux kernel 5.0+ (for `FAN_OPEN_EXEC_PERM`)
- `CAP_SYS_ADMIN` capability (or root) for fanotify
- SQLite3
- OpenSSL (for SHA256)
- GTK4 (for GUI client)

## Supported Distributions

| Distribution | Tested | Notes |
|--------------|--------|-------|
| **Ubuntu 20.04+** | ✅ | Kernel 5.4+, full support |
| **Ubuntu 22.04+** | ✅ | Kernel 5.15+, recommended |
| **Fedora 32+** | ✅ | Kernel 5.6+, full support |
| **Fedora 39/40** | ✅ | Kernel 6.x, recommended |
| **Debian 11+** | ✅ | Kernel 5.10+ |
| **Arch Linux** | ✅ | Rolling release, latest kernel |

Both RPM-based (Fedora, RHEL, CentOS) and DEB-based (Ubuntu, Debian) distributions are supported.

## Building

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install build-essential libsqlite3-dev libssl-dev libgtk-4-dev

# Install dependencies (Fedora)
sudo dnf install gcc make sqlite-devel openssl-devel gtk4-devel

# Build everything
make

# Or build components separately
make daemon
make gui
```

## Installation

```bash
sudo make install
sudo systemctl enable lexec-daemon
sudo systemctl start lexec-daemon
```

## Project Structure

```
Linux-anti-executable/
├── src/
│   ├── daemon/           # Root daemon (fanotify + whitelist)
│   │   ├── main.c
│   │   ├── fanotify.c    # fanotify handling
│   │   ├── whitelist.c   # SQLite whitelist management
│   │   ├── scanner.c     # Initial system scan
│   │   └── ipc.c         # Unix socket IPC
│   ├── gui/              # User interface
│   │   ├── main.c
│   │   ├── dialog.c      # Allow/Deny popup
│   │   └── manager.c     # Whitelist manager window
│   └── common/           # Shared code
│       ├── protocol.h    # IPC protocol definitions
│       └── hash.c        # SHA256 hashing
├── config/
│   ├── lexec.conf        # Configuration file
│   └── lexec-daemon.service  # systemd unit
├── sql/
│   └── schema.sql        # Database schema
└── scripts/
    └── first-run-scan.sh # Initial system scan helper
```

## Security Considerations

1. **Self-protection**: The daemon protects itself from termination
2. **Boot safety**: Essential system binaries are pre-whitelisted
3. **Atomic decisions**: No race conditions in allow/deny logic
4. **Tamper detection**: Whitelist database integrity checks

## Comparison with Windows Anti-Executable

| Feature | Windows Anti-Executable | Linux Anti-Executable |
|---------|------------------------|----------------------|
| Kernel integration | Filter driver | fanotify (no kernel module) |
| File identification | Path + Hash | SHA256 hash |
| Shared libraries | DLL monitoring | .so via fanotify |
| Scripts | .bat, .ps1, etc. | Shebang detection |
| User interface | Windows GUI | GTK4 |

## License

MIT License - See LICENSE file
