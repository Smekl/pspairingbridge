
import argparse
import logging
from scapy.all import Ether, IP, UDP

from .bridge import Sony, find_sony, listen_for_request_packet, send_discovery_response, __LOGGER__

def main():
    parser = argparse.ArgumentParser(
        description="Bridge for PS Remote Play discovery packets over VPNs/WAN.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Manual configuration group
    manual_group = parser.add_argument_group('Manual Configuration', 
                                             'Use these arguments to manually specify the PS5 details. '
                                             'This is useful if the PS5 is not discoverable via broadcast (e.g. over VPN).')
    
    manual_group.add_argument('--sony-ip', 
                              help='IP address of the PS5 (e.g., 192.168.0.100). \n'
                                   'If provided, you MUST also provide --sony-host-id.\n'
                                   'If NOT provided, the script attempts to auto-discover the PS5 on the local network.')
    manual_group.add_argument('--sony-host-id', 
                              help='Host ID of the PS5 (e.g., EC748CB56323). Required if --sony-ip is set.')
    manual_group.add_argument('--sony-host-type', default='PS5', 
                              help='Host Type (default: PS5).')
    manual_group.add_argument('--sony-host-name', 
                              help='Host Name (e.g., PS5-657).')
    manual_group.add_argument('--sony-host-request-port', default='997', 
                              help='Host Request Port (default: 997).')
    manual_group.add_argument('--sony-protocol-version', default='00030010', 
                              help='Device Discovery Protocol Version (default: 00030010).')
    manual_group.add_argument('--sony-system-version', default='09600004', 
                              help='System Version (default: 09600004).')

    # General options
    parser.add_argument('--interface', 
                        help='Network interface to bind/listen on (optional). '
                             'If not specified, scapy will listen on the default interface.')
    
    args = parser.parse_args()

    # Validation
    if args.sony_ip:
        if not args.sony_host_id:
            parser.error("--sony-host-id is required when --sony-ip is specified.")
        
        # We can construct the Sony object manually
        # Note: 'iface' and 'pkt' in Sony object are used for constructing the response.
        # When manual, we fake a packet path.
        # We need a dummy Ethernet/IP layer to extract src/dst for response construction if expected.
        # However, send_discovery_response uses sony.pkt to source args.
        
        # Construction of a dummy packet that mimics what find_sony would return
        sony = Sony(
            iface=None, 
            pkt=Ether(src="00:11:22:33:44:55") / IP(src=args.sony_ip) / UDP(sport=6070), 
            id=args.sony_host_id,
            type=args.sony_host_type,
            name=args.sony_host_name if args.sony_host_name else "Unknown-PS5",
            request_port=args.sony_host_request_port,
            proto_version=args.sony_protocol_version,
            system_version=args.sony_system_version
        )
        __LOGGER__.info('Got Sony info from arguments. Skipping discovery.')

    else:
        __LOGGER__.info("Looking for Sony in local network (Auto-Discovery)...")
        if args.interface:
             __LOGGER__.info(f"Scanning on specified interface: {args.interface}")
        
        sony = find_sony(interface=args.interface)
        
        if not sony:
            __LOGGER__.error("Could not find any PS5 device on the network. \n"
                             "Make sure the PS5 is on, connected to the same network, and has Remote Play enabled.\n"
                             "Alternatively, use manual configuration options (--sony-ip, --sony-host-id).")
            return

        __LOGGER__.info(f"Found Sony on interface {sony.iface.name} address {sony.pkt[IP].src}")


    __LOGGER__.info("Waiting for request packet from client...")
    pkt = listen_for_request_packet(interface=args.interface)
    
    if pkt:
        __LOGGER__.info(f"Got request from {pkt[IP].src} on iface {pkt.sniffed_on.name}. Responding...")
        send_discovery_response(sony, pkt)
        __LOGGER__.info("Done. Response sent.")
    else:
        __LOGGER__.warning("Bridge stopped or timed out without receiving a request.")

if __name__ == '__main__':
    main()