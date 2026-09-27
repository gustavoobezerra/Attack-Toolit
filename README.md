#  Attack Toolkit

Estrutura modular de scripts ofensivos organizados por categoria.

---

## Estrutura

```
paralelepipedo/
├── Web/              → Ataques e reconhecimento web
├── WiFi/             → Ataques a redes sem fio
├── Recon/            → Reconhecimento e enumeração
├── Network/          → Ataques de rede / MITM
├── Exploitation/     → Exploits e shells
└── Persistence/      → Persistência pós-exploração
```

---

## Web/

| Script | O que faz |
|---|---|
| `dos_http.py` | HTTP flood — 500 threads disparando GET requests |
| `dir_brute.py` | Força bruta de diretórios com wordlist |
| `sqli_probe.py` | Testa parâmetros URL contra payloads SQLi |
| `xss_probe.py` | Detecta reflexão XSS em parâmetros |
| `header_audit.py` | Audita cabeçalhos HTTP de segurança |

**Deps:** `pip install requests`

---

## WiFi/

| Script | O que faz |
|---|---|
| `deauth.py` | Envia frames 802.11 deauth (kick de clientes) |
| `handshake_capture.sh` | Captura handshake WPA/WPA2 via airodump-ng |
| `pmkid_attack.py` | Captura PMKID sem precisar de cliente conectado |
| `evil_twin.sh` | Cria AP falso clonando SSID alvo (captive portal) |

**Deps (Linux):** `scapy`, `aircrack-ng`, `hcxdumptool`, `hcxtools`, `hostapd`, `dnsmasq`

---

## Recon/

| Script | O que faz |
|---|---|
| `port_scanner.py` | Scanner TCP threaded com banner grab |
| `subdomain_enum.py` | Força bruta de subdomínios via DNS |
| `dns_enum.py` | Enumera registros DNS + tenta zone transfer |
| `banner_grab.py` | Captura banners de serviços em portas conhecidas |
| `whois_lookup.py` | WHOIS raw via socket |

**Deps:** `pip install dnspython`

---

## Network/

| Script | O que faz |
|---|---|
| `arp_spoof.py` | ARP poisoning para MITM (victim <-> gateway) |
| `syn_flood.py` | SYN flood com IPs spoofados via scapy |
| `mitm_sniffer.py` | Sniffa credenciais HTTP e cookies em trânsito |
| `dns_spoof.py` | DNS spoofing — redireciona domínios alvo |

**Deps (Linux root):** `pip install scapy` + `echo 1 > /proc/sys/net/ipv4/ip_forward`

---

## Exploitation/

| Script | O que faz |
|---|---|
| `reverse_shell.py` | Shell reverso — conecta de volta ao atacante |
| `bind_shell.py` | Bind shell — escuta na vítima |
| `lfi_probe.py` | Testa LFI via traversal de paths |
| `ssrf_probe.py` | Testa SSRF — acesso a metadata AWS/GCP/Azure e IPs internos |

**Listener reverso:** `nc -lvnp 4444`

---

## Persistence/

| Script | O que faz |
|---|---|
| `reg_persist.py` | Adiciona/remove entrada no Run key do registro (Windows) |
| `startup_drop.py` | Copia payload para pasta de startup (Windows/Linux) |

---

## Requisitos Globais

```bash
pip install requests scapy dnspython
```

Scripts de WiFi e Network requerem **Linux + root**.  
Scripts de Persistence/Windows requerem **Windows**.
