# TUI Fire

Monitor de red por proceso y firewall para Linux y Windows. La tabla muestra la velocidad de bajada y subida y los bytes acumulados desde que se abre la TUI. En Linux la fila seleccionada también muestra los bytes descartados y el número de sockets observados.

## Windows 10 y 11

Abre PowerShell o Windows Terminal como administrador y ejecuta el `.exe` desde su carpeta.

```powershell
.\tui-fire.exe
```

`--demo` abre la interfaz sin privilegios con datos simulados. `--check` prueba la captura de tráfico local IPv4 e IPv6 y el alta y la baja de filtros del firewall.

La medición usa los eventos TCP y UDP de ETW y muestra el consumo por PID. El bloqueo usa Windows Filtering Platform y afecta a todas las instancias que comparten la ruta del ejecutable. Las reglas se retiran al cerrar el programa. [Eventos de red ETW](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip) · [Sesiones temporales de WFP](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)

Para compilar en Windows con Rust y las herramientas de compilación de C++ de Visual Studio instaladas, ejecuta `cargo build --release --locked`. El binario queda en `target\release\tui-fire.exe`.

## Compilar y ejecutar en Omarchy

Requiere Rust y Cargo, un Clang con soporte eBPF, los headers de Linux y `libbpf` 1.x. El monitor se ejecuta con privilegios de administrador en un Linux de 64 bits con cgroup v2 y BTF del kernel en `/sys/kernel/btf/vmlinux`.

```sh
cargo build --release --locked
sudo ./target/release/tui-fire
```

La demo funciona desde una terminal interactiva sin privilegios. La autoprueba real abre sockets UDP locales y comprueba los contadores, el descarte de datagramas y la recuperación tras desbloquear en IPv4 e IPv6.

```sh
./target/release/tui-fire --demo
sudo ./target/release/tui-fire --check
```

## Controles

| Tecla | Acción |
| --- | --- |
| `↑` / `↓`, `j` / `k` | Seleccionar un proceso |
| `AvPág` / `RePág`, `Inicio` / `Fin` | Recorrer la lista |
| `/` | Buscar por parte del nombre o por PID exacto. `Intro` aplica y `Esc` cancela. |
| `f` | Cambiar entre todos, con tráfico, en curso y bloqueados |
| `1` a `6` | Ordenar por nombre, velocidad total, acumulado, bajada, subida o PID |
| `s` / `r` | Cambiar el criterio de ordenación o invertir su dirección |
| `b` | Bloquear o desbloquear la red del PID en Linux o del ejecutable en Windows |
| `?` / `q` | Mostrar la ayuda o salir |

## Alcance de la medición y del bloqueo en Linux

- La TUI lista los procesos visibles en `/proc`. Los procesos que terminaron conservan sus acumulados durante la sesión. Un PID reutilizado empieza con sus propios contadores y reglas.
- Los contadores miden bytes de paquetes IPv4 e IPv6 observados por eBPF en sockets, incluidos encabezados IP y tráfico local. La cifra **Sin atribuir** muestra tráfico observado que no se pudo asociar a un proceso. [Hooks de cgroup en Linux](https://github.com/torvalds/linux/blob/master/kernel/bpf/cgroup.c)
- El bloqueo actúa sobre los sockets del PID. Si dos procesos comparten un socket, bloquearlo afecta a ambos. Los sockets ya abiertos se identifican a través de `/proc` y los nuevos se registran al crearse. El tráfico que pasa por un proxy se atribuye al PID que tiene el socket IP. El tráfico fuera de los hooks IP, como los sockets Unix, queda fuera del alcance.
- Al cerrar TUI Fire, el kernel retira los hooks de esta ejecución y se levantan sus bloqueos. Las reglas duran una sesión.
