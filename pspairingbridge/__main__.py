"""
start a bridge that will listen for ps remote play discovery packets
and then forward the request to the ps and send back the response.

this script should be used when you have a zerotier or tailscale network
with a node that has one interface connected to your ps and another interface connected to the remote device (your tv for example)
you want to 
1. connect your tv over tailscale with the ps remote app
2. you want ps remote app to not use sony's internet servers
3. you want to teach ps remote app the sony's ip address that is reachable through zerotier / tailscale

just two packets - 
1. multicast service discovery for ps5
2. proxy the multicast to the ps5
3. proxy the ps5's response

python -m pspairingbridge --sony-ip 192.168.50.112 --sony-host-id EC748CB56323 --sony-host-type PS5 --sony-host-name PS5-657 --sony-host-request-port 997 --sony-protocol-version 00030010 --sony-system-version 09600004

example request from client -

SRCH * HTTP/1.1
device-discovery-protocol-version:00030010


example response from ps5 - 

HTTP/1.1 200 Ok
host-id:EC748CB56323
host-type:PS5
host-name:PS5-657
host-request-port:997
device-discovery-protocol-version:00030010
system-version:09600004

"""
import re
import time
import logging

import argparse
from scapy.all import *
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)

__LOGGER__ = logging.getLogger('ps5discovery')
PS_SERVICE_PORT = 9302
BPF = f'udp port {PS_SERVICE_PORT} and broadcast'
REQUEST_BPF = f'udp dst port {PS_SERVICE_PORT} and broadcast'
RESPONSE_BPF = f'udp src port {PS_SERVICE_PORT}' 

@dataclass
class Sony(object):
    iface: None
    pkt: None
    id: str
    type: str
    name: str
    request_port: int
    proto_version: str
    system_version: str

def filter_discovery_packet(pkt):
    if Raw in pkt:
        payload = pkt[Raw].load
        return b'device-discovery-protocol-version' in payload
    
    return False

def listen_for_request_packet(interface=None):
    return sniff(iface=interface, filter=REQUEST_BPF, lfilter=filter_discovery_packet, stop_filter=filter_discovery_packet)[0]

def prepare_discovery_request(proto_version='00030010'):
    return f"""SRCH * HTTP/1.1\r\ndevice-discovery-protocol-version:{proto_version}\r\n\r\n"""

def prepare_discovery_response(host_id, host_type, host_name, host_request_port, proto_version, system_version):
    return f"""HTTP/1.1 200 Ok\r\nhost-id:{host_id}\r\nhost-type:{host_type}\r\nhost-name:{host_name}\r\nhost-request-port:{host_request_port}\r\ndevice-discovery-protocol-version:{proto_version}\r\nsystem-version:{system_version}\r\n\r\n"""

def send_discovery_response(sony: Sony, request_packet):
    payload = prepare_discovery_response(sony.id, sony.type, sony.name, sony.request_port, sony.proto_version, sony.system_version)
    pkt = Ether() / IP() / UDP() / payload
    pkt[Ether].src = sony.pkt[Ether].src
    pkt[Ether].dst = request_packet[Ether].src
    pkt[IP].src = sony.pkt[IP].src
    pkt[IP].dst = request_packet[IP].src
    pkt[UDP].sport = sony.pkt[UDP].sport
    pkt[UDP].dport = request_packet[IP].sport
    sendp(pkt, iface=request_packet.sniffed_on.name)

def find_sony():
    payload = prepare_discovery_request()
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="255.255.255.255") / UDP(sport=1020, dport=9302) / payload
    for ifname in get_if_list():
        iface = conf.ifaces[ifname]
        if not iface.ip or not iface.mac or iface.ip == '127.0.0.1':
            continue

        sniffer = AsyncSniffer(iface=iface.name, filter=RESPONSE_BPF, quiet=True)
        sniffer.start()
        __LOGGER__.debug(f'try {ifname} -> {iface.name}')
        pkt[Ether].src = iface.mac
        pkt[IP].src = iface.ip
        sendp(pkt, iface=iface.name, verbose=False)
        time.sleep(0.5)
        pkts = sniffer.stop()
        if len(pkts) > 0:
            pkt = pkts[0]
            payload = pkt[Raw].load
            host_id, host_type, name, request_port, proto_ver, sys_ver = re.findall(b"[\w-]+:([\w-]+)", payload)
            return Sony(iface, pkt, host_id.decode(), host_type.decode(), name.decode(), request_port.decode(), proto_ver.decode(), sys_ver.decode())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sony-ip')
    parser.add_argument('--sony-host-id')
    parser.add_argument('--sony-host-type', default='PS5')
    parser.add_argument('--sony-host-name')
    parser.add_argument('--sony-host-request-port', default='997')
    parser.add_argument('--sony-protocol-version', default='00030010')
    parser.add_argument('--sony-system-version', default='09600004')

    args = parser.parse_args()

    if not args.sony_ip:
        __LOGGER__.info("looking for sony in local network")
        sony = find_sony()
        __LOGGER__.info(f"found sony on interface {sony.iface.name} address {sony.pkt[IP].src}")

    else:
        sony = Sony(iface=None, pkt=Ether(src="00:11:22:33:44:55") / IP(src=args.sony_ip) / UDP(sport=6070), 
                    id=args.sony_host_id,
                    type=args.sony_host_type,
                    name=args.sony_host_name,
                    request_port=args.sony_host_request_port,
                    proto_version=args.sony_protocol_version,
                    system_version=args.sony_system_version)
                    
        __LOGGER__.info('got sony info from arguments. skipping discovery.')

    __LOGGER__.info("waiting for request packet")
    pkt = listen_for_request_packet()
    __LOGGER__.info(f"got request from {pkt[IP].src} on iface {pkt.sniffed_on.name}. responding..")
    send_discovery_response(sony, pkt)
    __LOGGER__.info("done")


if __name__ == '__main__':
    main()