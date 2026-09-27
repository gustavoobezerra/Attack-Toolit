# Recon — Tutorial

## Dependencias
```bash
pip install dnspython
```

---

## port_scanner.py
Scanner TCP rapido com 200 threads e banner grab automatico.

```bash
python port_scanner.py
# Target: 192.168.1.1
# Port range: 1-65535
```

**Output exemplo:**
```
[OPEN] 192.168.1.1:22   SSH-2.0-OpenSSH_8.2
[OPEN] 192.168.1.1:80   HTTP/1.1 200 OK
[OPEN] 192.168.1.1:443
```

Ajuste `THREADS` para velocidade. Em redes lentas reduza para 50.

---

## subdomain_enum.py
Força bruta de subdominios via resolucao DNS com 100 threads.

```bash
python subdomain_enum.py
# Domain: target.com
# Wordlist: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Wordlists:
- SecLists: `https://github.com/danielmiessler/SecLists`
- `Discovery/DNS/` pasta com varios tamanhos

---

## dns_enum.py
Enumera todos os tipos de registro DNS e tenta zone transfer (AXFR).

```bash
python dns_enum.py
# Domain: target.com
```

Zone transfer bem-sucedido revela TODOS os hosts/subdominios de uma vez.  
Se `[AXFR] Zone transfer SUCCEEDED` aparecer: jackpot.

---

## banner_grab.py
Conecta em portas e le o banner inicial do servico.

```bash
python banner_grab.py
# Target: 10.0.0.1
# Ports: 21,22,25,80,443,3306   <- especificas
# Ports: (enter)                <- portas comuns pre-definidas
```

Banners revelam versao do servico — cruzar com CVEs:
```bash
# Exemplo: banner mostra OpenSSH 7.2
searchsploit openssh 7.2
```

---

## whois_lookup.py
Consulta WHOIS raw via socket seguindo cadeia de referrals da IANA.

```bash
python whois_lookup.py
# Domain or IP: target.com
```

Revelam: registrante, emails, nameservers, datas de registro/expiracao, ASN.
