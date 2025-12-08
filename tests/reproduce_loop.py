import socket
import subprocess
import time
import sys
import threading
import os
import signal

# Ajustar ruta al binario si es necesario
PROXY_BIN = './build/bin/socks5d'
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 1080
ORIGIN_PORT = 8888

def start_origin_server(shutdown_event):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(('127.0.0.1', ORIGIN_PORT))
        server_sock.listen(1)
        server_sock.settimeout(5.0)
        
        try:
            conn, addr = server_sock.accept()
            # print(f"Origin accepted: {addr}")
            time.sleep(1)
            conn.close() # Cierra conexión para provocar el escenario
        except socket.timeout:
            pass
            # print("Origin timeout waiting for connection")
            
    finally:
        server_sock.close()
        shutdown_event.set()

def run_test():
    if not os.path.exists(PROXY_BIN):
        print(f"Error: No se encuentra el binario {PROXY_BIN}")
        print("Ejecuta este script desde la raíz del proyecto (donde esta Makefile) y asegura que 'make' se haya ejecutado.")
        return

    print("Iniciando Proxy...")
    # Ejecutamos el proxy capturando stdout para ver si loopea
    # Usamos preexec_fn=os.setsid para crear un grupo de procesos y poder matarlo limpiamente
    proxy_process = subprocess.Popen(
        [PROXY_BIN],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        preexec_fn=os.setsid 
    )
    
    time.sleep(1) # Esperar a que levante
    
    shutdown_event = threading.Event()
    origin_thread = threading.Thread(target=start_origin_server, args=(shutdown_event,))
    origin_thread.start()
    
    time.sleep(0.5)
    
    client = None
    try:
        print("Conectando cliente...")
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((PROXY_HOST, PROXY_PORT))
        
        # Handshake
        client.sendall(b'\x05\x01\x00')
        resp = client.recv(2)
        if resp != b'\x05\x00':
            print(f"Error en handshake: {resp}")
            return

        # Request connect
        # Connect to 127.0.0.1:8888
        port_bytes = ORIGIN_PORT.to_bytes(2, 'big')
        req = b'\x05\x01\x00\x01\x7f\x00\x00\x01' + port_bytes
        client.sendall(req)
        
        resp = client.recv(10)
        if len(resp) < 10 or resp[1] != 0x00:
            print(f"Error en request: {resp}")
            return
            
        print("Túnel establecido. Cliente en espera (sin enviar datos)...")
        print("El origen cerrará la conexión en 1 segundo.")
        
        # Esperamos un momento despues de que el origen cierre
        # Si el bug esta presente, el proxy entrará en loop consumiendo CPU y generando logs si los hay.
        
        time.sleep(3)
        
        print("Test finalizado. Verificando output...")
        
    except Exception as e:
        print(f"Excepción en cliente: {e}")
    finally:
        if client:
            client.close()
            
        # Matamos al proxy
        os.killpg(os.getpgid(proxy_process.pid), signal.SIGTERM)
        
        try:
            outs, _ = proxy_process.communicate(timeout=2)
            lines = outs.splitlines()
            print(f"Total lineas de log del proxy: {len(lines)}")
            # Debug: imprimir algunas lineas si hay muchas
            if len(lines) > 2000:
                print("FAIL: Se detectó una cantidad excesiva de logs. Probable LOOP INFINITO.")
                print("Ultimas 20 lineas:")
                for l in lines[-20:]:
                    print(l)
            else:
                print("PASS: Cantidad de logs razonable. No parece haber loop infinito (o no loguea en el loop).")
                if len(lines) > 0:
                    print("Log output (last 5 lines):")
                    for l in lines[-5:]:
                        print(l)
                
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proxy_process.pid), signal.SIGKILL)
            print("Proxy forzado a cerrar (timeout).")

if __name__ == "__main__":
    run_test()
