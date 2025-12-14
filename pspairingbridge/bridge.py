
import re
import time
import logging
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

def find_sony(interface=None):
    payload = prepare_discovery_request()
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="255.255.255.255") / UDP(sport=1020, dport=9302) / payload
    # TODO: Refactor to allow specific interface, currently iterates all.
    # Logic kept similar to original for now, but `interface` arg could be used to filter `get_if_list()`
    
    for ifname in get_if_list():
        if interface and interface != ifname:
             continue

        iface = conf.ifaces[ifname]
        try:
             if not iface.ip or not iface.mac or iface.ip == '127.0.0.1':
                continue
        except AttributeError:
             continue # Some interfaces might not have accessible attributes

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
            # Basic parsing
            try:
                host_id, host_type, name, request_port, proto_ver, sys_ver = re.findall(b"[\w-]+:([\w-]+)", payload)
                return Sony(iface, pkt, host_id.decode(), host_type.decode(), name.decode(), request_port.decode(), proto_ver.decode(), sys_ver.decode())
            except Exception as e:
                __LOGGER__.error(f"Failed to parse packet payload: {e}")
                continue
    return None
