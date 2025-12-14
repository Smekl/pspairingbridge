# PSPairingBridge

A bridge that listens for PS Remote Play discovery packets and forwards requests to the PS5, sending back the response. This is useful for using PS Remote Play over ZeroTier, Tailscale, or other VPNs where broadcast discovery doesn't work natively.

## Installation

```bash
pip install .
```

## Usage

You can run the bridge using the command line interface:

```bash
# General usage
pspairingbridge --help

# Example: Run with manual Sony IP and Host ID (skipping discovery)
pspairingbridge --sony-ip 192.168.50.112 --sony-host-id EC748CB56323 --sony-host-type PS5 --sony-host-name PS5-657 --sony-host-request-port 997 --sony-protocol-version 00030010 --sony-system-version 09600004
```

Or let it auto-discover if on the same network:

```bash
pspairingbridge
```

## How it Works

1.  Listens for multicast service discovery packets from the PS Remote Play app.
2.  Proxies the multicast request to the PS5 (unicast).
3.  Proxies the PS5's response back to the client.
