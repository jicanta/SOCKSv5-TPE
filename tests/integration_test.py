import socket
import struct
import threading
import time
import sys

# Configuration
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 1080
# Assuming you have a user 'foo' with pass 'bar' in your args.c or hardcoded
USER = b'foo'
PASS = b'bar'

def connect_socks5(sock):
    # 1. HELLO
    # Version 5, 1 Method (User/Pass = 0x02)
    sock.sendall(b'\x05\x01\x02')
    response = sock.recv(2)
    if response != b'\x05\x02':
        return False, f"Handshake failed: {response}"

    # 2. AUTH
    # Version 1, User len, User, Pass len, Pass
    auth_msg = b'\x01' + bytes([len(USER)]) + USER + bytes([len(PASS)]) + PASS
    sock.sendall(auth_msg)
    response = sock.recv(2)
    if response != b'\x01\x00':
        return False, f"Auth failed: {response}"
    
    return True, "OK"

def test_auth_failure():
    print("[TEST] Authentication Failure...", end=" ")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((PROXY_HOST, PROXY_PORT))
        s.sendall(b'\x05\x01\x02') # Hello
        s.recv(2)
        
        # Send wrong password
        bad_user = b'bad'
        bad_pass = b'wrong'
        auth_msg = b'\x01' + bytes([len(bad_user)]) + bad_user + bytes([len(bad_pass)]) + bad_pass
        s.sendall(auth_msg)
        
        response = s.recv(2)
        # Expecting version 1, status != 0
        if response[0] == 1 and response[1] != 0:
            print("PASSED")
        else:
            print(f"FAILED (Got success response: {response})")
    except Exception as e:
        print(f"FAILED (Exception: {e})")
    finally:
        s.close()

def test_unsupported_method():
    print("[TEST] Unsupported Method...", end=" ")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((PROXY_HOST, PROXY_PORT))
        # Version 5, 1 Method (GSSAPI = 0x01), Server only supports 0x02 or 0x00
        s.sendall(b'\x05\x01\x01') 
        response = s.recv(2)
        
        # Expecting Version 5, Method 0xFF (No acceptable methods)
        if response == b'\x05\xff':
            print("PASSED")
        else:
            print(f"FAILED (Got: {response})")
    except Exception as e:
        print(f"FAILED (Exception: {e})")
    finally:
        s.close()

def test_google_connect():
    print("[TEST] Connect to Google (Data Transfer)...", end=" ")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((PROXY_HOST, PROXY_PORT))
        ok, msg = connect_socks5(s)
        if not ok:
            print(f"FAILED ({msg})")
            return

        # 3. REQUEST (Connect to google.com:80)
        # Ver 5, Cmd 1 (Connect), Rsv 0, Atyp 3 (Domain), Len 10, google.com, Port 80
        domain = b'google.com'
        req = b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + struct.pack('!H', 80)
        s.sendall(req)
        
        # Read Reply
        # We expect at least 4 bytes initially, but the full reply is variable
        # Ver 5, Rep 0 (Success), Rsv 0, Atyp...
        reply = s.recv(4)
        if reply[1] != 0:
            print(f"FAILED (SOCKS Request failed with code {reply[1]})")
            return
            
        # Consume the rest of the address (IPv4=4+2, IPv6=16+2, Domain=1+Len+2)
        # For simplicity, just read a chunk, we don't care about the bind addr for this test
        s.recv(1024) 

        # 4. DATA TRANSFER
        req_http = b"GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n"
        s.sendall(req_http)
        
        data = s.recv(4096)
        if b"HTTP/1.1" in data or b"google" in data:
            print("PASSED")
        else:
            print("FAILED (No HTTP response received)")
            
    except Exception as e:
        print(f"FAILED (Exception: {e})")
    finally:
        s.close()

def test_concurrency():
    print("[TEST] Concurrency (500 connections)...", end=" ")
    threads = []
    errors = []

    def worker():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((PROXY_HOST, PROXY_PORT))
            ok, _ = connect_socks5(s)
            if not ok:
                errors.append("Auth fail")
            s.close()
        except:
            errors.append("Connect fail")

    for _ in range(500):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

    if len(errors) == 0:
        print("PASSED")
    else:
        print(f"FAILED ({len(errors)} errors)")

if __name__ == "__main__":
    print("--- SOCKS5 Integration Tests ---")
    # Wait a bit to ensure server is up if run immediately after start
    time.sleep(1) 
    
    test_auth_failure()
    test_unsupported_method()
    test_google_connect()
    test_concurrency()