import subprocess

def scan_networks():
    try:
        # Run nmcli to scan WiFi networks
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,RATE,SECURITY", "device", "wifi", "list"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print("Error scanning networks:", result.stderr)
            return

        networks = result.stdout.strip().split("\n")
        print(f"Found {len(networks)} network(s):\n")

        for network in networks:
            # Split using ':' as the delimiter but respect the BSSID structure
            parts = network.split(":")
            
            if len(parts) >= 6:
                ssid = parts[0]
                bssid = ":".join(parts[1:7])  # Combine the first 6 segments for BSSID
                channel = parts[7]
                signal = parts[8]
                rate = parts[9]
                security = parts[10] if len(parts) > 10 else "Unknown"

                print(f"SSID: {ssid}")
                print(f"BSSID: {bssid}")
                print(f"Channel: {channel}")
                print(f"Signal: {signal}%")
                print(f"Rate: {rate}")
                print(f"Security: {security}")
                print("-" * 40)
            else:
                print(f"Skipping malformed entry: {network}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    scan_networks()
