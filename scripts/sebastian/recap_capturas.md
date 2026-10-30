# Recap de capturas — Retos de Sebastian (Execute y Last Call)

Lista de screenshots que hay que tomar para completar `documentacion.md`. Cada
captura va guardada en `segu_p2/imagenes/` con el **nombre exacto** indicado (así
el `![...](imagenes/...)` del documento la encuentra sin tocar nada más).

Corré todo desde la carpeta de cada reto en tu VM de Linux (donde está el binario).

---

## Reto Execute (sección 1.3)

### 1. `execute_checksec.png` — Paso 1 (Reconocimiento)
Protecciones del binario; lo clave es que la pila es ejecutable / sin NX.
```bash
checksec --file=execute
# (o:  pwn checksec execute )
file execute
```
Capturá la salida de ambos comandos.

### 2. `execute_blacklist.png` — Paso 2 (Vulnerabilidad)
Mostrar la lista negra de 16 bytes dentro de `check()` y/o la línea que ejecuta
el buffer. Con el código fuente (`pwn_execute/execute.c`) basta:
```bash
cat execute.c
```
O si lo hacés por binario, en Ghidra la función `check`/`main`, o:
```bash
objdump -d -M intel execute | less    # buscar la comparacion de bytes
```
Capturá donde se vean los bytes `3b 54 62 69 6e 73 68 ...` o el arreglo blacklist.

### 3. `execute_flag.png` — Paso 3 (Explotación)
El shellcode (guardado como texto en `shellcode_perl.txt`) enviado con
`printf "$(cat ...)" | nc` contra la instancia de HTB y la bandera real
(método manual que usaste, sin pwntools):
```bash
( printf "$(cat shellcode_perl.txt)" ; sleep 0.5 ; echo 'cat flag.txt' ; cat ) | nc <IP> <PUERTO>
```
(El archivo `shellcode_perl.txt` ya está en `scripts/sebastian/Execute/`.)
Capturá la shell abierta y la salida de `cat flag.txt` con el `HTB{...}` real.

---

## Reto Last Call (sección 1.4)

### 1. `lastcall_nm.png` — Paso 1 (Reconocimiento)
`file` + `checksec` + los símbolos listados con `nm`:
```bash
file last_call
checksec --file=last_call
nm last_call | grep -iE "vault|jingle|closing|submit|view|cabinet"
```
Capturá las tres salidas (se ven `default_jingle 0x8999`, `open_vault_for_real
0x89cd`, `closing_time`, `submit_score`, `view_slot`, `cabinet`).

### 2. `lastcall_closing_time.png` — Paso 2 (Vulnerabilidad)
El desensamblado que prueba el bug: `closing_time` llamando a `[cabinet+0x1e8]`
y el chequeo `idx <= 10` de `submit_score`.
```bash
objdump -d -M intel last_call | grep -A15 "<closing_time>:"
objdump -d -M intel last_call | grep -A25 "<submit_score>:"
```
Capturá donde se vea `call rax` sobre `cabinet+0x1e8` y el `cmp ... 0xa`.
(No hace falta Ghidra: el binario no está stripped, con objdump basta.)

### 3. `lastcall_flag.png` — Paso 3 (Explotación)
El exploit corriendo contra la instancia de HTB con la fuga y la bandera:
```bash
python3 exploit.py <IP> <PUERTO>
```
Capturá las líneas `default_jingle fugado / base PIE / open_vault_for_real` y, al
final, el `HTB{...}` real (asegurate de que diga *Opening connection to...* y NO
*Starting local process*, para que sea la bandera del remoto y no la de prueba).

---

## Estado — COMPLETO para Execute y Last Call

Ya quedaron en `documentacion.md`:

- **Execute:** Very Easy, 260 XP, 7/10/2026, bandera `HTB{0947aed1bdfe357f8e9033c8c874c590}`.
- **Last Call:** Very Easy, 260 XP, 26/10/2026, bandera `HTB{th3_l3ad3rb04rd_w4s_n3v3r_th3_p01nt}`.
- Calendario, tabla resumen (Sebastian 520 XP) y puntos acumulados (1040 / 2300).

## Lo que falta para el proyecto (no para estos dos retos)

- Llegar a **2300 XP** (van 1040).
- **Al menos 2 retos de Reversing** y **2 de Web** (por ahora los 4 resueltos son Pwn).
