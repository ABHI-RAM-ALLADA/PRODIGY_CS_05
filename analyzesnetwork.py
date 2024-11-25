from scapy.all import sniff

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}, Protocol: {ip_layer.proto}")
        
        # If the packet has a load (like TCP or UDP), show the payload
        if packet.haslayer('TCP') or packet.haslayer('UDP'):
            payload = packet.payload
            print(f"Payload: {payload}")
        print("-" * 50)

def start_sniffer(interface=None):
    print("Starting packet sniffer...")
    # Start sniffing packets
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Specify the network interface to sniff on (e.g., 'eth0', 'wlan0')
    # Leave as None to sniff on all interfaces
    start_sniffer(interface=None)