# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based networking tool that creates a WireGuard tunnel between macOS and Podman containers running in a Linux VM. It enables direct Layer 3 connectivity to containers by IP address without port binding.

## Architecture

The project consists of two main components:

1. **Main Server (`main.go`)**: Runs on macOS, creates a WireGuard interface (`utun`), and manages network routes
2. **Client Container (`client/main.go`)**: Runs inside the Podman VM to configure the WireGuard peer

### Key Components

- **`networkmanager/`**: Handles macOS network interface configuration and routing table management
- **`version/`**: Contains version information and container image references
- **`client/`**: Container-based WireGuard client that runs in the Podman VM

## Common Development Commands

### Building
```bash
# Build the main Go binary
make build-go

# Build and push client container images (amd64 and arm64)
make build-podman

# Build everything
make build
```

### Running
```bash
# Run locally (requires root for network interface creation)
sudo make run-go

# Full build and run
make run
```

### Testing
```bash
# Run Go tests
go test ./...

# Test the application end-to-end
make run
```

## Architecture Details

### Process Flow
1. Main process inspects running Podman processes via `ps aux` to extract SSH connection details
2. Loads WireGuard kernel module in the Podman VM via SSH
3. Creates WireGuard tunnel between macOS host and Podman VM
4. Monitors Podman networks and automatically adds/removes routes to macOS routing table
5. Deploys a privileged container in the VM to configure the WireGuard peer

### Network Configuration
- Host peer IP: `10.33.34.1`
- VM peer IP: `10.33.34.2`
- WireGuard port: `3334`
- Interface name: `utun` (macOS), `madawg0` (Linux VM)

### Key Dependencies
- **WireGuard**: Core tunneling technology
- **Podman bindings**: For container and network management
- **netlink**: Linux network interface management (client)
- **iptables**: NAT configuration (client)

## Development Notes

- The main binary must run as root for network interface creation
- The client container requires `NET_ADMIN` capability and `--net=host`
- SSH key discovery is performed by parsing process arguments from `gvproxy`
- Version information is embedded at build time via Go linker flags