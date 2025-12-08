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
- **Shared library monitoring**: Tracks .so files loaded via dlopen()
- **Persistence**: Approved files remain approved across reboots
- **System protection**: Critical system files auto-whitelisted

## Technical Requirements

- Linux kernel 5.0+ (for `FAN_OPEN_EXEC_PERM`)
- `CAP_SYS_ADMIN` capability (or root) for fanotify
- SQLite3
- GTK4 (for GUI client)

## Building

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install build-essential libsqlite3-dev libgtk-4-dev

# Build daemon
cd src/daemon
make

# Build GUI
cd src/gui
make
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
