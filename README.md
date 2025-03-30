![Terminal](https://github.com/user-attachments/assets/7a4f7681-fc87-494d-921f-a32eb56ee109)
# 🛡️ Network Security Toolkit (Packet Burn) 


## 📌 Sobre o Projeto  
Este projeto foi desenvolvido para **fins educacionais e de pesquisa** em **cibersegurança e redes**. Ele permite que os usuários explorem conceitos fundamentais de **segurança de redes**, como **escaneamento de dispositivos**, **desautenticação de clientes Wi-Fi** e **ataques de ARP spoofing**.  

> ⚠ **Aviso Legal:** Este projeto é destinado **exclusivamente ao aprendizado e experimentação em ambientes controlados**. O uso indevido pode ser ilegal. O autor **não se responsabiliza** por qualquer mau uso.  

## 🚀 Funcionalidades  
✅ **Network Scanner:** Detecta dispositivos conectados ao roteador e exibe seus endereços IP e MAC.  
✅ **Deauth Attack:** Simula a desconexão de dispositivos de uma rede Wi-Fi (**requer modo monitor**).  
✅ **ARP Spoofing:** Intercepta e redireciona tráfego entre vítimas e o gateway.  
✅ **ARP Spoofing Killer:** Variante mais agressiva do ARP Spoofing, enviando pacotes maliciosos continuamente.  

## 🛠 Requisitos  
Para utilizar esta ferramenta, você precisará de:  
- **Python 3.x** instalado no sistema.  
- As seguintes bibliotecas:  
  ```bash
  pip install termcolor scapy netifaces
  ```
- Uma **interface de rede configurada no modo monitor** (*necessário para ataques Deauth*).  
- **Permissões de superusuário (root)** para enviar pacotes brutos.  

### 📌 Executando no Windows  
Se deseja rodar o projeto no **Windows**, será necessário instalar o **Npcap** para capturar pacotes de rede.  

1. Baixe e instale o Npcap: [https://nmap.org/npcap/](https://nmap.org/npcap/)  
2. Instale as dependências mencionadas anteriormente.  
3. Execute o script com permissões elevadas (**como administrador**):  
   ```powershell
   python PacketBur.py
   ```
> ⚠ Algumas funcionalidades, como o ataque Deauth, podem **não funcionar corretamente no Windows** devido a limitações no suporte ao modo monitor.  

## 🎯 Como Usar  
Para iniciar, execute o script:  
```bash
sudo python3 PacketBurn.py
```  
Escolha uma opção no menu interativo:  

🔄 **Atualizar lista de dispositivos:** Faz um novo escaneamento e exibe dispositivos ativos.  
🎯 **Selecionar um alvo:** Escolha um dispositivo específico e selecione o tipo de ataque.  
🔥 **Atacar todos os dispositivos (exceto o seu):** Executa ataques simultâneos.  
❌ **Sair:** Fecha o programa.  

## ⚠ Considerações Importantes  
- Utilize **somente para fins educacionais** e **dentro de redes autorizadas**.  
- Respeite as **leis locais** sobre testes de segurança.  
- O uso indevido desta ferramenta **pode resultar em consequências legais**.  

Este projeto foi criado para fins de **aprendizado e pesquisa**, ajudando **entusiastas e profissionais** a entender vulnerabilidades de redes e desenvolver **técnicas de defesa**.  

