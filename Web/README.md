# Web — Tutorial

## Dependencias
```bash
pip install requests
```

---

## dos_http.py
HTTP flood com 500 threads. Satura o servidor web com requisicoes GET em loop.

```bash
python dos_http.py
# Target URL: http://192.168.1.100
```

Ajuste `THREADS` no topo para mais pressao. Funciona em Layer 7 (HTTP).  
Para Layer 4 (SYN flood) use `Network/syn_flood.py`.

---

## dir_brute.py
Descobre diretorios e arquivos ocultos com wordlist.

```bash
python dir_brute.py
# Target URL: http://target.com
# Wordlist: /usr/share/wordlists/dirb/common.txt
```

Wordlists recomendadas:
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/big.txt`
- `https://github.com/danielmiessler/SecLists`

Resultados mostram codigos HTTP diferentes de 404.

---

## sqli_probe.py
Testa parametros URL contra 13 payloads SQLi. Detecta por mensagens de erro no HTML.

```bash
python sqli_probe.py
# Target URL: http://target.com/page?id=1&cat=news
```

Detecta: MySQL, PostgreSQL, SQLite, ORA-, erros de sintaxe.  
Se encontrar `[VULN]`: use `sqlmap` para extração completa:
```bash
sqlmap -u "http://target.com/page?id=1" --dbs
```

---

## xss_probe.py
Injecta 9 payloads XSS em parametros e verifica reflexao na resposta.

```bash
python xss_probe.py
# Target URL: http://target.com/search?q=test
```

`[REFLECTED]` = parametro reflete input sem sanitizar — potencial XSS.  
Verifique manualmente no browser para confirmar execucao de JS.

---

## header_audit.py
Audita cabecalhos HTTP de seguranca.

```bash
python header_audit.py
# Target URL: https://target.com
```

| Flag | Significado |
|------|-------------|
| `[WARN]` | Header de seguranca ausente |
| `[OK]` | Header presente |
| `[INFO LEAK]` | Header revela tecnologia (Server, X-Powered-By) |
