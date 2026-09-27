# PasswordCracking — Tutorial

## Dependencias
```bash
pip install requests
# hashcat: https://hashcat.net/hashcat/
# john:    apt install john  (Linux)
```

---

## hash_identifier.py
Identifica o tipo de hash pelo padrão.
```bash
python hash_identifier.py
# Hash: 5f4dcc3b5aa765d61d8327deb882cf99
# Possible: MD5
```

---

## hashcat_wrapper.py
Interface simplificada pro hashcat com os modos mais comuns.
```bash
python hashcat_wrapper.py
# Mode: 0            <- MD5
# Hash file: hashes.txt
# Wordlist: /usr/share/wordlists/rockyou.txt
# Rules: (blank)
# Output: cracked.txt
```
**Modos comuns:**
| Modo | Tipo |
|------|------|
| 0 | MD5 |
| 100 | SHA1 |
| 1000 | NTLM (Windows) |
| 1400 | SHA256 |
| 3200 | bcrypt |
| 22000 | WPA2 (handshake) |
| 5600 | NetNTLMv2 |

```bash
# Crackear WPA2 direto:
hashcat -m 22000 capture.22000 rockyou.txt
```

---

## john_wrapper.py
Wrapper pro John the Ripper.
```bash
python john_wrapper.py
# Hash file: shadow.txt
# Format: sha512crypt
# Wordlist: rockyou.txt
# Rules: best64
```
Ver resultados:
```bash
john --show shadow.txt
```

---

## credential_stuffing.py
Testa lista de user:pass contra endpoint de login.

**Formato do combo file:**
```
admin:admin
root:toor
user@email.com:password123
```

```bash
python credential_stuffing.py
# URL: http://target.com/login
# Method: POST
# Username field: email
# Password field: password
# Combo file: combos.txt
# Success string: Welcome    <- texto que aparece quando loga
# Fail string: Invalid      <- ou texto de falha
```

> Ajuste THREADS e DELAY no topo do script para controlar velocidade.
