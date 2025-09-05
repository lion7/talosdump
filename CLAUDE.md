# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TalosDump is a Wireshark extcap plugin for capturing network packets from Talos Linux nodes. It allows Wireshark to capture network traffic directly from Talos Linux machines by implementing the extcap interface protocol.

## Architecture

The application is a single Go binary that:
1. Implements the Wireshark extcap protocol to integrate with Wireshark as a capture interface
2. Connects to Talos Linux nodes via the Talos client API
3. Enumerates available network interfaces across Talos cluster members
4. Captures packets from selected interfaces with optional BPF filtering
5. Streams captured packets back to Wireshark in real-time

Key components:
- `main.go`: All functionality in a single file
- Uses Talos machinery client to communicate with nodes
- Uses extcap library for Wireshark integration
- Supports physical ethernet and bridge interfaces only

## Common Commands

```bash
# Build the binary
make build
# or directly
go build -o talosdump-linux-amd64

# Install to Wireshark extcap directory (user-specific)
make install

# Create a GitHub release
make release

# Run tests (no tests currently exist)
go test ./...

# Update dependencies
go mod tidy
```

## Development Notes

- The binary must be installed in Wireshark's extcap directory to be recognized
- Default installation path: `~/.local/lib/wireshark/extcap/talosdump`
- Requires Talos configuration (talosconfig) to connect to nodes
- Interface format: `linkname@hostname` (e.g., `eth0@node1`)
