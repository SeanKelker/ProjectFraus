from typing import Dict, Any

import pyshark
import time

# Wifi info to decrypt 802.11 packets
WPA_PASSWORD = 'gosantaclara'
NETWORK_SSID = 'SCU-Student'

# Defines how long in seconds sniffing will occur before
# data processing begins
RUN_TIME = 30

# Global variables to track seen devices and packet sources
devices = dict()


class Packet:

    def __init__(self, pkt):
        # Record time when packet was sniffed
        self.time = time.time()

        # Currently extracting packet info by using key for specific layer. This
        # should not error because check had already been dont to see that these
        # layers exist. Should be changed if the protocols read become more fluid.

        # MAC LAYER
        # Data of interest: Source Mac Address, Destination Mac Address
        mac_layer = pkt['WLAN']
        self.src_mac_addr = mac_layer.addr
        self.dst_mac_addr = mac_layer.da

        # NETWORK LAYER
        # Data of interest: Source IP Address, Destination IP Address
        network_layer = pkt['IP']
        self.src_ip_addr = network_layer.src
        self.dst_ip_addr = network_layer.dst

        # Currently only looking for UDP and TCP packets but should be
        # to be more generic
        if 'udp' in [layer.layer_name for layer in pkt.layers]:
            transport_layer = pkt['UDP']
            self.transport_layer_type = 'udp'
        else:
            transport_layer = pkt['TCP']
            self.transport_layer_type = 'tcp'

        # TRANSPORT LAYER
        # Data of interest: Source Port, Destination Port
        self.src_port = transport_layer.srcport
        self.dst_port = transport_layer.dstport
        print(self.src_port, self.dst_port)


# Class stores a lost of packets which is identified byt its
# mac address representing a unique device
class PacketSource:
    def __init__(self, mac):
        self.mac = mac
        self.packets = []

    def __hash__(self):
        return hash(self.mac)

    def add_packet(self, pkt):
        self.packets.append(pkt)


def extract_layers(pkt):
    # Check that the layers we want exist in this packet
    packet_layers = [layer.layer_name for layer in pkt.layers]
    # Like the Packet object this should be updated to be for generic
    if 'ip' in packet_layers and ('udp' in packet_layers or 'tcp' in packet_layers):
        mac = pkt['WLAN'].addr

        # Devices are tracked by there mac address as a key in the devices dict
        if mac in devices:
            source = devices[mac]
            source.add_packet(Packet(pkt))
        else:
            new_source = PacketSource(mac)
            devices[mac] = new_source
            new_source.add_packet(Packet(pkt))


# Create a capture interface live or reading from a local file
def create_capture(live_capture=False):
    if live_capture:
        cap = pyshark.LiveCapture(interface="en0",
                                  monitor_mode=True,
                                  encryption_type="wpa-pwd",
                                  decryption_key=WPA_PASSWORD + ":" + NETWORK_SSID, )
        cap.sniff(timeout=1)
    else:
        cap = pyshark.FileCapture('capture.cap')
    return cap


def main():
    capture = create_capture()
    start_time = time.time()
    for pkt in capture:
        extract_layers(pkt)
        if time.time() - start_time >= RUN_TIME:
            break


if __name__ == "__main__":
    main()
