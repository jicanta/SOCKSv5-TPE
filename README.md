# SOCKSv5-TPE

**Project**: SOCKSv5 Proxy

**Integrantes**: Juan Ignacio Cantarella, Máximo Daniel Carranza, Lola Díaz Varela y Lucas Di Candia 

- **Descripción**: Implementación de un proxy SOCKSv5 concurrente y no bloqueante. Soporta autenticación usuario/contraseña (RFC1929), resolución FQDN, IPv4/IPv6 y tests de integración incluidos.

**Build**
- **Requisitos**: `gcc`, `make`, `python3` (para tests de integración).
- **Compilar**: limpia y compila el proyecto.
	```bash
	make clean all
	```
- **Salida**: el ejecutable del servidor proxy queda en `build/bin/socks5d`.

**Run Server**
- **Ejecutar servidor**: arranca el proxy con el usuario `foo:bar` (obligatorio para el test de integración).
	```bash
	./build/bin/socks5d -u foo:bar
	```
- **Ejecutar en background**:
	```bash
	./build/bin/socks5d -u foo:bar > server.log 2>&1 &
	```
- **Opciones**:
	- `-l <SOCKS addr>`: dirección donde escuchará el proxy (default `0.0.0.0`).
	- `-p <SOCKS port>`: puerto SOCKS (default `1080`).
	- `-u <name>:<pass>`: agrega un usuario.
	- `-L <conf addr>` / `-P <conf port>`: dirección/puerto para la interfaz de management (si está implementada).
	- Para más opciones ver `src/shared/args.c` y el `Makefile`.

**Integration Test**
- **Ubicación**: `tests/integration_test.py`.
- **Requisito del test**: asume que el servidor está corriendo y que existe el usuario `foo:bar`. Se debe arrancar el servidor con `-u foo:bar` antes de ejecutar el script.
- **Ejecutar**:
	```bash
	# En una terminal: arrancar servidor (puerto 1080 por defecto)
	./build/bin/socks5d -u foo:bar > server.log 2>&1 &

	# En otra terminal: ejecutar test de integración
	python3 tests/integration_test.py
	```
- **Detener el servidor**:
	```bash
	pkill -f build/bin/socks5d
	```

**Logs y Auditoría**
- Actualmente el servidor escribe eventos a `stdout`/`stderr` (p. ej. autenticaciones y accesos). Para la entrega final implementaremos logging/métricas como lo indica la consigna.
	- Se redirigir la salida a un fichero para conservar registros, por ejemplo `> server.log 2>&1`.

**Plots de benchmarks de buffer**
- Script: `python3 scripts/plot_buffer_benchmark.py <resultados.csv> --out plots`
- Expectativa del CSV: columnas de tamaño de buffer (bytes), tamaño de archivo (bytes), throughput en Mbps (o duración en segundos para calcularlo) y un flag de modo/proxy opcional.
- Salida: PNGs con throughput vs tamaño de buffer por cada tamaño de archivo y un promedio general. Opción `--linear-x` si no querés eje log2.
- Dependencias: `pandas` y `matplotlib` (`python3 -m pip install pandas matplotlib` si no los tenés).
- Para generar el CSV localmente: `scripts/benchmark_buffer.sh` (requiere `curl`, `python3`, `make`, `dd`). Por defecto barre buffers densos (512 B hasta 1 MiB). Podés limpiar runs previos con `rm buffer_benchmark.csv plots/*.png` antes de volver a medir/graficar.

**Notas / Limitaciones**
- El test de integración espera el usuario `foo:bar` — arrancá el servidor con `-u foo:bar` tal como está indicado.
- Algunas funcionalidades de la consigna (exposición de métricas persistentes, gestión completa en tiempo de ejecución y logging rotativo) no se encuentran aún implementadas.
