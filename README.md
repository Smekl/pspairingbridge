# PSPairingBridge

A bridge that listens for PS Remote Play discovery packets and forwards requests to the PS5, sending back the response. This is useful for using PS Remote Play over ZeroTier, Tailscale, or other VPNs where broadcast discovery doesn't work natively.

## Installation

```bash
pip install .
```

## Usage

You can run the bridge using the command line interface `pspairingbridge`.

### Auto-Discovery Mode
If your machine is on the same broadcast domain as the PS5 (e.g. WiFi), you can simply run:

```bash
pspairingbridge
```
You can also specify a network interface to scan on:
```bash
pspairingbridge --interface "Ethernet 2"
```

### Manual Mode (VPN/Remote)
If you are over a VPN (ZeroTier, Tailscale) and broadcast packets don't reach the PS5, you must manually provide the PS5's IP and Host ID.

```bash
pspairingbridge --sony-ip <PS5_IP> --sony-host-id <HOST_ID>
```

**Required Arguments for Manual Mode:**
*   `--sony-ip`: The IP address of your PS5 (e.g., `192.168.1.50`).
*   `--sony-host-id`: The unique Host ID of your console.

**Optional Arguments:**
*   `--sony-host-name`: Name of the console (visual only).
*   `--sony-host-type`: Type of console (default: `PS5`).
*   `--sony-host-request-port`: Port (default: `997`).

## How it Works

1.  Listens for multicast service discovery packets from the PS Remote Play app.
2.  Proxies the multicast request to the PS5 (unicast) or uses manually provided details.
3.  Proxies the PS5's response back to the client.
