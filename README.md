![Terminal](https://github.com/user-attachments/assets/7a4f7681-fc87-494d-921f-a32eb56ee109)
# PacketBurn – Network Security Toolkit

**PacketBurn** is an educational and research-oriented toolkit for network security enthusiasts, designed to demonstrate real‑world network attack techniques in controlled environments.

> **⚠ Legal Notice:** This project is strictly intended for educational and experimentation purposes in authorized environments only. Unauthorized or malicious use may violate laws, and the author is not responsible for any misuse.

### Features

- **Network Scanner**: Discovers devices connected to the router and displays their IP and MAC addresses.
- **Deauthentication Attack**: Simulates disconnecting devices from a Wi‑Fi network (requires monitor mode).
- **ARP Spoofing**: Intercepts and redirects traffic between victim devices and the gateway.
- **ARP Spoofing Killer**: A more aggressive version of ARP Spoofing, continuously sending spoofed packets.

### Requirements

- Python 3.x
- Required libraries:

  ```bash
  pip install termcolor scapy netifaces
  ```

- A network interface in **monitor mode** (required for Deauth attacks)
- **Superuser (root) privileges** to send raw packets

### Running on Windows

If you're using Windows:

1. Install **Npcap** for packet capture: https://nmap.org/npcap/
2. Install the dependencies listed above.
3. Run the script with elevated privileges, e.g.:

   ```bash
   python PacketBurn.py
   ```

> **Note:** Some features (e.g. Deauth attack) may not function properly on Windows due to limited support for monitor mode.

### Usage Instructions

Run the tool with:

```bash
sudo python3 PacketBurn.py
```

You’ll be prompted with an interactive menu:

1. **Refresh device list** – Scan and list active devices.
2. **Select a target** – Choose a device and apply an attack type.
3. **Attack all devices (excluding yours)** – Perform simultaneous attacks.
4. **Exit** – Quit the program.

### Important Considerations

- Use strictly for educational purposes within networks you have permission to test.
- Respect local laws and regulations surrounding network security.
- Misuse of this tool may result in legal consequences.
- This project is aimed at helping security learners and professionals understand network vulnerabilities and develop defensive techniques.

---

## About PacketBurn

PacketBurn is a Python‑based **Network Security Toolkit** crafted for cybersecurity practitioners, students, and educators keen on exploring real‑world network vulnerabilities. Designed as a learning resource, PacketBurn offers an immersive look into essential security concepts such as device discovery, Wi‑Fi deauthentication, and ARP-based attacks.

Whether you're studying for certifications, conducting controlled security research, or teaching network security fundamentals, PacketBurn provides clear, actionable insight into common attack methods—and how they can be mitigated.

Built for simplicity and educational clarity, PacketBurn delivers:

- Interactive and hands‑on learning via command‑line menus
- Modular design suitable for adaptation and extension
- Cross-platform compatibility (Linux, with partial support on Windows via Npcap)
- Safe experimentation when used responsibly in authorized environments

Dive into PacketBurn to uncover how modern networks can be compromised—and how you can prevent it.
