import statistics
import time

import matplotlib.pyplot as plt
import pyshark

# Wifi info to decrypt 802.11 packets
WPA_PASSWORD = ''
NETWORK_SSID = ''

# Defines how long in seconds sniffing will occur before data processing
# begins. If None data will process until EOF or interrupted.
SNIFF_TIME = None

# Packets transmitted in < BURST_DELTA are defined to be in the same burst
BURST_DELTA = 1

# These number translate between the qos priority values the AC type of each packet
BK_1 = 1
BK_2 = 2
BE_1 = 0
BE_2 = 3
VI_1 = 4
VI_2 = 5
VO_1 = 6
VO_2 = 7

# Global variables to track seen devices and packet sources
_devices = dict()

# If defined will split traffic into AP and interfering traffic
AP_MAC_address = ''

# Will generate graphs if set to true
GENERATE_GRAPHS = False

INFILE = 'Captures/ip.pcap'
f = open(r'out.txt', 'w+')


# Wrapper class to ingest and store packers
class Packet:

    def __init__(self, pkt):
        try:

            packet_layers = [layer.layer_name for layer in pkt.layers]

            # Record time when packet was sniffed
            self.time = int(pkt.sniff_time.timestamp() * 1000)

            # Length of packet in bytes
            self.length = int(pkt.length)

            # Currently extracting packet info by using key for specific layer. This
            # should not error because check had already been dont to see that these
            # layers exist. Should be changed if the protocols read become more fluid.

            # WLAN_RADIO
            self.data_rate = None
            self.noise = None
            self.snr = None
            # MAC LAYER
            self.src_mac_addr = None
            self.dst_mac_addr = None
            # WLAN
            self.duration = None
            self.frame_type = None
            self.frame_subtype = None
            self.pwr_mgt = None
            self.access_category = None

            if 'wlan_radio' in packet_layers:
                wlan_radio = pkt['WLAN_RADIO']
                self.data_rate = float(wlan_radio.data_rate)

                self.noise = None
                if hasattr(wlan_radio, 'noise_dbm'):
                    self.noise = int(wlan_radio.noise_dbm)

                self.snr = None
                if hasattr(wlan_radio, 'snr'):
                    self.snr = float(wlan_radio.snr)
            else:
                self.data_rate = None
                self.noise = None
                self.snr = None

            if 'wlan' in packet_layers:

                mac_layer = pkt['WLAN']
                self.src_mac_addr = mac_layer.ta
                self.dst_mac_addr = mac_layer.ra

                self.duration = None
                if hasattr(mac_layer, 'duration'):
                    self.duration = int(mac_layer.duration)

                self.frame_type = mac_layer.fc_type
                self.frame_subtype = mac_layer.fc_type_subtype

                self.pwr_mgt = mac_layer.fc_pwrmgt

                self.access_category = None
                if hasattr(mac_layer, 'qos_priority'):
                    self.access_category = int(mac_layer.qos_priority)

            if 'eth' in packet_layers:
                mac_layer = pkt['ETH']

                self.src_mac_addr = mac_layer.src
                self.dst_mac_addr = mac_layer.dst



        except AttributeError as e:
            # If we try and access a field that doesnt exist in the packet just
            # drop the packet and move on
            pass


# Class stores a lost of packets which is identified by its
# mac address representing a unique device
class Device:
    def __init__(self, mac):
        self.mac = mac
        self.sent = []
        self.recv = []

    def add_recv_packet(self, pkt):
        self.recv.append(pkt)

    def add_sent_packet(self, pkt):
        self.sent.append(pkt)


# Given a list of data points will write statistical info to out file
def analyze_set(data):
    if len(data) == 0:
        f.write('\t\tNo Data\n')
        return

    set_mean = statistics.mean(data)
    f.write('\t\tMean: ' + str(set_mean) + '\n')

    set_min = min(data)
    f.write('\t\tMin: ' + str(set_min) + '\n')

    set_max = max(data)
    f.write('\t\tMax: ' + str(set_max) + '\n')

    set_median = statistics.median(data)
    f.write('\t\tMedian: ' + str(set_median) + '\n')

    # standard dev requires sets with at least two points
    if len(data) <= 1:
        return
    set_standard_dev = statistics.stdev(data)
    f.write('\t\tStandard Deviation: ' + str(set_standard_dev) + '\n')


def process_packets(packets):
    pass
    if len(packets) == 0:
        f.write('\tNo packets to process' + '\n')
        return

    # Packets can come in out of order so sort list of timestamps to parse
    # in order
    packets = sorted(packets, key=lambda pkt: pkt.time)

    # SENT PACKET LENGTH
    f.write('\tPacket Length (bytes):' + '\n')
    length = [pkt.length for pkt in packets]
    analyze_set(length)

    f.write('\tPacket Duration (microseconds):' + '\n')
    duration = [pkt.duration for pkt in packets if pkt.duration is not None]
    analyze_set(duration)

    f.write('\tData Rate (Mb/s):' + '\n')
    data_rate = [pkt.data_rate for pkt in packets if pkt.data_rate is not None]
    analyze_set(data_rate)

    f.write('\tNoise (dBm):' + '\n')
    noise = [pkt.noise for pkt in packets if pkt.noise is not None]
    analyze_set(noise)

    f.write('\tSignal/Noise Ratio (dBm):' + '\n')
    snr = [pkt.snr for pkt in packets if pkt.snr is not None]
    analyze_set(snr)

    bursts_time = []
    bursts_length = []
    bursts_bytes = []
    interval = []

    burst_start = None
    burst_end = None
    burst_count = 0
    byte_count = 0
    # This loop tracks bursts while looping through all packets. Checks whether
    # each consecutive packet is in the same burst and then updates the lists
    # accordingly.
    for pkt in packets:
        if burst_start is None:
            burst_start = pkt.time
            burst_end = pkt.time
            burst_count += 1
            byte_count += pkt.length
        elif pkt.time - burst_end <= BURST_DELTA:
            burst_end = pkt.time
            burst_count += 1
            byte_count += pkt.length
        else:
            if burst_start != burst_end:
                bursts_time.append(burst_end - burst_start)
                bursts_length.append(burst_count)
                bursts_bytes.append(byte_count)
                interval.append(pkt.time - burst_end)
            burst_start = pkt.time
            burst_end = pkt.time
            burst_count = 1
            byte_count = pkt.length
    if burst_start != burst_end:
        bursts_time.append(burst_end - burst_start)
        bursts_length.append(burst_count)
        bursts_bytes.append(byte_count)

    f.write('\tBurst Duration (Milliseconds) \n')
    analyze_set(bursts_time)
    f.write('\tPackets per Burst:\n')
    analyze_set(bursts_length)
    f.write('\tBytes per Burst:\n')
    analyze_set(bursts_bytes)
    f.write('\tInterval Duration (Milliseconds):\n')
    analyze_set(interval)
    f.write('\tBurstiness:\n')

    if len(bursts_bytes) > 0 and len(bursts_time) > 0 and len(interval) > 0:
        bursts = statistics.mean(bursts_bytes)
        burstd = statistics.mean(bursts_time)
        bursti = statistics.mean(interval)
        burstiness = (bursts / burstd) * bursti
        f.write('\t\t' + str(burstiness) + '\n')
    else:
        f.write('\t\tNo Data\n')


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

def create_subplot(subplot, packets, title='', color=None):
    subplot.set_title(title)

    packets_timestamps = [pkt.time for pkt in packets]
    # It is possible that a device only send or received
    # Only looking at graphs with >2 packets to avoid empty graphs
    if len(packets_timestamps) == 0:
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

    subplot.plot(millisecond_bucket, color=color)


def extract_layers(pkt):
    # Check that the layers we want exist in this packet
    packet_layers = [layer.layer_name for layer in pkt.layers]
    if 'wlan' not in packet_layers and 'eth' not in packet_layers:
        print('fuck')
        return


    pkt = Packet(pkt)

    src_mac = pkt.src_mac_addr
    dst_mac = pkt.dst_mac_addr

    # Devices are tracked by there mac address as a key in the devices dict
    # Add packets to to sending and receiving device
    if src_mac in _devices:
        source = _devices[src_mac]
        source.add_sent_packet(pkt)
    else:
        new_source = Device(src_mac)
        _devices[src_mac] = new_source
        new_source.add_sent_packet(pkt)

    if dst_mac in _devices:
        source = _devices[dst_mac]
        source.add_recv_packet(pkt)
    else:
        new_source = Device(dst_mac)
        _devices[dst_mac] = new_source
        new_source.add_recv_packet(pkt)


# Given a list of packets extract lists of packets for each AC type
def extract_ac(packets):
    bk = [pkt for pkt in packets if pkt.access_category is not None and
          (pkt.access_category == BK_1 or pkt.access_category == BK_2)]

    be = [pkt for pkt in packets if pkt.access_category is not None and
          (pkt.access_category == BE_1 or pkt.access_category == BE_2)]

    vi = [pkt for pkt in packets if pkt.access_category is not None and
          (pkt.access_category == VI_1 or pkt.access_category == VI_2)]

    vo = [pkt for pkt in packets if pkt.access_category is not None and
          (pkt.access_category == VO_1 or pkt.access_category == VO_2)]

    return bk, be, vi, vo


# Given a device object function will parse and analyze all segments of packet
def analyze_device(dev):
    # The basic flow is after all the packets have been ingested pass all the
    # packets to be analyzed. After extract the access category type based on
    # the qos priority and pass that set of packets to be analyzed.

    # Sent Packets
    f.write('Device: ' + dev.mac + ' (Sent)\n')
    process_packets(dev.sent)

    sent_bk, sent_be, sent_vi, sent_vo = extract_ac(dev.sent)

    f.write('Device: ' + dev.mac + ' (Sent BK)\n')
    process_packets(sent_bk)
    f.write('Device: ' + dev.mac + ' (Sent BE)\n')
    process_packets(sent_be)
    f.write('Device: ' + dev.mac + ' (Sent VI)\n')
    process_packets(sent_vi)
    f.write('Device: ' + dev.mac + ' (Sent VO)\n')
    process_packets(sent_vo)

    # Received Packets
    f.write('Device: ' + dev.mac + ' (Received)\n')
    process_packets(dev.recv)

    recv_bk, recv_be, recv_vi, recv_vo = extract_ac(dev.recv)
    f.write('Device: ' + dev.mac + ' (Received BK)\n')
    process_packets(recv_bk)
    f.write('Device: ' + dev.mac + ' (Received BE)\n')
    process_packets(recv_be)
    f.write('Device: ' + dev.mac + ' (Received VI)\n')
    process_packets(recv_vi)
    f.write('Device: ' + dev.mac + ' (Received VO)\n')
    process_packets(recv_vo)

    if GENERATE_GRAPHS:
        if len(dev.sent) + len(dev.recv) > 10:
            fig, axs = plt.subplots(2, 5)
            fig.set_size_inches(25, 15)

            create_subplot(axs[0][0], dev.sent, 'Sent')
            create_subplot(axs[0][1], sent_bk, 'BK')
            create_subplot(axs[0][2], sent_be, 'BE')
            create_subplot(axs[0][3], sent_vi, 'VI')
            create_subplot(axs[0][4], sent_vo, 'VO')

            create_subplot(axs[1][0], dev.recv, 'Recv')
            create_subplot(axs[1][1], recv_bk, 'BK')
            create_subplot(axs[1][2], recv_be, 'BE')
            create_subplot(axs[1][3], recv_vi, 'VI')
            create_subplot(axs[1][4], recv_vo, 'VO')
            fig.suptitle(dev.mac, fontsize=16)
            plt.savefig('plots/' + dev.mac + '.png')
            plt.close()


# Create a capture interface live or reading from a local file
def create_capture(live_capture=False):
    if live_capture:
        cap = pyshark.LiveCapture(interface='en0', monitor_mode=True,
                                  encryption_type='wpa-pwd')
        cap.sniff(timeout=1)
    else:
        cap = pyshark.FileCapture(input_file=INFILE)
    return cap


def main():
    capture = create_capture()
    start_time = time.time()

    print(capture.load_packets(packet_count=100))

    for pkt in capture:
        extract_layers(pkt)
        if SNIFF_TIME is not None and time.time() - start_time > SNIFF_TIME:
            break

    if AP_MAC_address == '':
        # To analyze properties of the entire network dump all packets into list
        all_packets = []
        for mac in list(_devices):
            dev = _devices[mac]
            # All packets have been added to a sent and received so the sum of one
            # of the packets seen by the network
            all_packets = all_packets + dev.senth66

        f.write('Aggregate Network Data:\n')
        process_packets(all_packets)

        all_bk, all_be, all_vi, all_vo = extract_ac(all_packets)
        f.write('Aggregate Network Data (BK):\n')
        process_packets(all_bk)
        f.write('Aggregate Network Data (BE):\n')
        process_packets(all_be)
        f.write('Aggregate Network Data (VI):\n')
        process_packets(all_vi)
        f.write('Aggregate Network Data (VO):\n')
        process_packets(all_vi)

        # Once packet read is completed begin data process
        for mac in list(_devices):
            dev = _devices[mac]
            analyze_device(dev)

    else:
        ap = _devices[AP_MAC_address]
        f.write('AP Data:\n')
        analyze_device(ap)

        interfering = Device('Interfering')
        for mac in list(_devices):
            dev = _devices[mac]
            for pkt in dev.sent:
                if pkt.src_mac_addr != AP_MAC_address and pkt.dst_mac_addr != pkt.src_mac_addr:
                    interfering.add_sent_packet(pkt)
            for pkt in dev.recv:
                if pkt.src_mac_addr != AP_MAC_address and pkt.dst_mac_addr != pkt.src_mac_addr:
                    interfering.add_recv_packet(pkt)

        f.write('Interfering Data:\n')
        analyze_device(interfering)


if __name__ == '__main__':
    main()
