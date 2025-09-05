# TalosDump

TalosDump is a Wireshark extcap plugin that enables packet capture from [Talos Linux](https://www.talos.dev/) nodes directly within Wireshark. It provides seamless integration with Wireshark's interface, allowing you to capture and analyze network traffic from remote Talos Linux machines as easily as capturing from local interfaces.

## Features

- Direct packet capture from Talos Linux nodes through Wireshark
- Support for multiple network interfaces across cluster nodes
- BPF (Berkeley Packet Filter) support for capture filtering
- Real-time packet streaming to Wireshark
- Automatic enumeration of available interfaces across all cluster members

## Requirements

- Wireshark installed on your local machine
- Access to a Talos Linux cluster with a valid talosconfig file
- Network connectivity to your Talos nodes

## Installation

### Option 1: Build from Source

1. Clone the repository:
```bash
git clone https://github.com/lion7/talosdump.git
cd talosdump
```

2. Build and install:
```bash
make install
```

This will compile the binary and install it to `~/.local/lib/wireshark/extcap/talosdump`.

### Option 2: Download Pre-built Binary

1. Download the latest release from [GitHub Releases](https://github.com/lion7/talosdump/releases)

2. Make the binary executable:
```bash
chmod +x talosdump-linux-amd64
```

3. Move it to Wireshark's extcap directory:
```bash
mkdir -p ~/.local/lib/wireshark/extcap
mv talosdump-linux-amd64 ~/.local/lib/wireshark/extcap/talosdump
```

## Configuration

TalosDump uses your Talos configuration file (talosconfig) to connect to nodes. Ensure you have a valid talosconfig in one of these locations:
- `~/.talos/config`
- Or set via the `TALOSCONFIG` environment variable

**Note:** Your talosconfig must have at least one node configured. TalosDump needs explicit node configuration to enumerate and connect to cluster members.

## Usage

1. Launch Wireshark
2. In the capture interface list, you'll see TalosDump interfaces listed as `linkname@hostname` (e.g., `eth0@node1`)
3. Select the interface you want to capture from
4. Start capturing as you would with any other interface

### Capture Filters

TalosDump supports BPF filters using Wireshark's capture filter syntax. 

**Important:** When setting capture filters, ensure you exclude the PCAP transmission traffic itself to avoid capturing the capture stream. Either use a more specific filter for your needs, or explicitly exclude port 50000 (the default Talos API port) by adding `not port 50000` to your filter expression.

## Flatpak Wireshark Users

If you're using Wireshark installed via Flatpak, you need to enable network access for TalosDump to communicate with your Talos nodes.

### Option 1: Using Flatseal

1. Install Flatseal (if not already installed)
2. Open Flatseal and select Wireshark
3. Enable "Network" permission under the Socket section

### Option 2: Command Line

Launch Wireshark with network access enabled:
```bash
flatpak run --share=network org.wireshark.Wireshark
```

## Troubleshooting

- **No TalosDump interfaces visible**: Ensure the binary is in the correct extcap directory and is executable
- **Connection errors**: Verify your talosconfig is valid and you have network connectivity to your Talos nodes
- **No packets captured**: Check that the selected interface is active and has traffic

## License

See LICENSE file in the repository for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests on [GitHub](https://github.com/lion7/talosdump).