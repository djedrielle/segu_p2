import angr

p = angr.Project('restaurant', auto_load_libs=False)
state = p.factory.entry_state()
simgr = p.factory.simulation_manager(state)

simgr.run()

print(f"Total de caminos finalizados (deadends): {len(simgr.deadended)}")

# Analizar cada estado que llegó a un final
for i, dead_state in enumerate(simgr.deadended):
    # Obtener la dirección exacta donde terminó
    print(f"\n--- Estado Deadend #{i} ---")
    print(f"Dirección final: {hex(dead_state.addr)}")
    
    # Opcional: ver qué imprimió el programa en la salida estándar (stdout) antes de morir
    stdout_output = dead_state.posix.dumps(1) # Descriptor 1 = stdout
    if stdout_output:
        print(f"Salida en pantalla antes de morir: {stdout_output}")
        
    # Opcional: ver qué entrada (stdin) generó este camino específico
    stdin_input = dead_state.posix.dumps(0) # Descriptor 0 = stdin
    if stdin_input:
        print(f"Entrada necesaria para llegar aquí: {stdin_input}")