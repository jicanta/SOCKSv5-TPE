import socket
import threading
import time
import sys

# Configuration
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 1080
CONCURRENT_CONNECTIONS = 500

def connect_and_hold(index, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((PROXY_HOST, PROXY_PORT))
        
        # Simple handshake to verify it's working
        # Version 5, 1 Method (No Auth) - or whatever the server accepts
        # The server code seems to accept Method 0x02 (User/Pass) or 0x00 (No Auth) depending on config?
        # Let's just send the initial greeting and wait for response.
        s.sendall(b'\x05\x01\x00') 
        resp = s.recv(2)
        
        # Just hold the connection
        time.sleep(5)
        s.close()
        results[index] = True
    except Exception as e:
        # print(f"Connection {index} failed: {e}")
        results[index] = False

def test_concurrency():
    print(f"Starting concurrency test with {CONCURRENT_CONNECTIONS} connections...")
    threads = []
    results = [False] * CONCURRENT_CONNECTIONS
    
    start_time = time.time()
    
    for i in range(CONCURRENT_CONNECTIONS):
        t = threading.Thread(target=connect_and_hold, args=(i, results))
        threads.append(t)
        t.start()
        # Small delay to avoid overwhelming the OS immediately if needed
        # time.sleep(0.001) 
        
    for t in threads:
        t.join()
        
    end_time = time.time()
    
    success_count = sum(results)
    print(f"Finished in {end_time - start_time:.2f} seconds.")
    print(f"Successful connections: {success_count}/{CONCURRENT_CONNECTIONS}")
    
    if success_count == CONCURRENT_CONNECTIONS:
        print("SUCCESS: Server handled all concurrent connections.")
        sys.exit(0)
    else:
        print("FAILURE: Some connections failed.")
        sys.exit(1)

if __name__ == "__main__":
    test_concurrency()
