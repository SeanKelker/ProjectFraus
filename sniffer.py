import statistics
import time

import matplotlib.pyplot as plt
import pyshark

# Wifi info to decrypt 802.11 packets
WPA_PASSWORD = 'gosantaclara'
NETWORK_SSID = 'SCU-Student'

# Defines how long in seconds sniffing will occur before
# data processing begins
SNIFF_TIME = 500

# Packets transmitted in < BURST_DELTA are defined to be in the same burst
BURST_DELTA = 20

# Global variables to track seen devices and packet sources
_devices = dict()


# TODO: Ask what VL and DL are

class Packet:

    def __init__(self, pkt):
        # Record time when packet was sniffed
        self.time = int(pkt.sniff_time.timestamp() * 1000)

        # Length of packet in bytes
        self.length = int(pkt.length)

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


# Class stores a lost of packets which is identified by its
# mac address representing a unique device
# TODO: Split into sent and recv to avoid repeated code
class Device:
    def __init__(self, mac):

        self.mac = mac
        # TRANSMITTED PACKETS
        self.sent_packets = []
        self.sent_packets_timestamps = []

        self.sent_burst_count = 0
        self.sent_burst_begin_time = 0
        self.sent_bursts = []

        # RECEIVED PACKETS
        self.recv_packets = []
        self.recv_packets_timestamps = []

        self.recv_burst_count = 0
        self.recv_burst_begin_time = 0
        self.recv_bursts = []

    def __hash__(self):
        return hash(self.mac)

    # TODO: Fix more repeated code
    def add_recv_packet(self, pkt):
        # Track received
        recv_time = pkt.time
        self.recv_packets.append(pkt)
        self.recv_packets_timestamps.append(recv_time)

        # State machine to track bursts
        # Will not track bursts of only one packet
        # If not a burst start tracking
        if self.recv_burst_begin_time == 0:
            self.recv_burst_begin_time = recv_time
            self.recv_burst_count += 1
        # If the next packet is outside the time delta the previous burst
        # has ended and should be saved
        elif recv_time - self.recv_burst_begin_time >= BURST_DELTA:
            self.recv_bursts.append((self.recv_burst_begin_time, recv_time,
                                     self.recv_burst_count))
            self.recv_burst_begin_time = 0
            self.recv_burst_count = 0
        # Else mid burst and should keep tracking
        else:
            self.recv_burst_count += 1

    def add_sent_packet(self, pkt):
        # Track received
        sent_time = pkt.time
        self.sent_packets.append(pkt)
        self.sent_packets_timestamps.append(sent_time)

        # State machine to track bursts
        # Will not track bursts of only one packet

        # If not a burst start tracking
        if self.sent_burst_begin_time == 0:
            self.sent_burst_begin_time = sent_time
            self.sent_burst_count += 1
        # If the next packet is outside the time delta the previous burst
        # has ended and should be saved
        elif sent_time - self.sent_burst_begin_time >= BURST_DELTA:
            self.sent_bursts.append((self.sent_burst_begin_time,
                                     sent_time, self.sent_burst_count))
            self.sent_burst_begin_time = 0
            self.sent_burst_count = 0
        # Else mid burst and should keep tracking
        else:
            self.sent_burst_count += 1


def analyze_set(data):
    # TODO: Save data to text file
    if len(data) == 0:
        print('\t\tNo Data')
        return
    set_mean = statistics.mean(data)
    print('\t\tMean: ', set_mean)
    set_min = min(data)
    print('\t\tMin: ', set_min)
    set_max = max(data)
    print('\t\tMax:', set_max)
    set_median = statistics.median(data)
    print('\t\tMedian:', set_median)
    # TODO: Add HQ and LQ


def process_packets(dev):
    print("Device: " + dev.mac)

    # SENT PACKET LENGTH
    print('\tSent Packet Length:')
    sent_length = [pkt.length for pkt in dev.sent_packets]
    analyze_set(sent_length)

    # RECV PACKET LENGTH
    print('\tRecv Packet Length:')
    recv_length = [pkt.length for pkt in dev.recv_packets]
    analyze_set(recv_length)

    # TODO: I really seem to like repeated code here
    # SENT BURST
    sent_burst_length = []
    sent_burst_count = []
    for burst in dev.sent_bursts:
        start_time, end_time, num_packets = burst
        sent_burst_length.append(end_time - start_time)
        sent_burst_count.append(num_packets)
    print('\tSent Burst Time:')
    analyze_set(sent_burst_length)
    print('\tPackets per Sent Burst:')
    analyze_set(sent_burst_count)

    # RECV BURST
    recv_burst_length = []
    recv_burst_count = []
    for burst in dev.sent_bursts:
        start_time, end_time, num_packets = burst
        recv_burst_length.append(end_time - start_time)
        recv_burst_count.append(num_packets)
    print('\tRecv Burst Time:')
    analyze_set(recv_burst_length)
    print('\tPackets per Recv Burst:')
    analyze_set(recv_burst_count)

    # TODO: Add inter
    # TODO: Add duration


def visualize_packets(packets_timestamps, title=''):
    # It is possible that a device only send or received
    # Only looking at graphs with >2 packets to avoid empty graphs
    if len(packets_timestamps) <= 2:
        return

    init_time = packets_timestamps[0]
    end_time = packets_timestamps[-1]

    # Determine how many milliseconds span the first and last packet received
    time_span = end_time - init_time + 1

    # Count how many packets were sent per millisecond
    millisecond_bucket = [0] * time_span
    for pkt_time in packets_timestamps:
        time_relative = pkt_time - init_time
        millisecond_bucket[time_relative] += 1

    plt.title(title)
    plt.xlabel('Time (milliseconds)')
    plt.ylabel('Packets')
    plt.plot(millisecond_bucket)
    plt.show()


def extract_layers(pkt):
    # Check that the layers we want exist in this packet
    packet_layers = [layer.layer_name for layer in pkt.layers]
    # Like the Packet object this should be updated to be for generic
    if 'ip' in packet_layers and ('udp' in packet_layers or 'tcp' in packet_layers):
        src_mac = pkt['WLAN'].ta
        dst_mac = pkt['WLAN'].ra

        # Devices are tracked by there mac address as a key in the devices dict
        # Add packets to to sending and receiving device
        if src_mac in _devices:
            source = _devices[src_mac]
            source.add_sent_packet(Packet(pkt))
        else:
            new_source = Device(src_mac)
            _devices[src_mac] = new_source
            new_source.add_sent_packet(Packet(pkt))

        if dst_mac in _devices:
            source = _devices[dst_mac]
            source.add_recv_packet(Packet(pkt))
        else:
            new_source = Device(dst_mac)
            _devices[dst_mac] = new_source
            new_source.add_recv_packet(Packet(pkt))


# Create a capture interface live or reading from a local file
def create_capture(live_capture=False):
    if live_capture:
        cap = pyshark.LiveCapture(interface="en0",
                                  monitor_mode=True,
                                  encryption_type="wpa-pwd",
                                  decryption_key=WPA_PASSWORD + ":" + NETWORK_SSID)
        cap.sniff(timeout=1)
    else:
        cap = pyshark.FileCapture(input_file='capture.pcapng')
    return cap


def main():
    capture = create_capture()
    start_time = time.time()

    for pkt in capture:
        extract_layers(pkt)
        if time.time() - start_time >= SNIFF_TIME:
            break

    # Once packet read is completed begin data process
    for mac in list(_devices):
        dev = _devices[mac]
        process_packets(dev)
        visualize_packets(dev.sent_packets_timestamps, 'Transmitted: ' + dev.mac)
        visualize_packets(dev.recv_packets_timestamps, 'Received: ' + dev.mac)


if __name__ == "__main__":
    main()
