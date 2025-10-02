# server.py
import socket
import threading
from handlers import manejar_cliente
import crypto

def iniciar_servidor(HOST="192.168.20.71", PORT=5000, MAX_CLIENTES=10):
    rsa_key = crypto.generate_rsa_keypair()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(MAX_CLIENTES)

    print(f"Servidor escuchando en {HOST}:{PORT} (máx {MAX_CLIENTES} clientes)...")

    while True:
        conn, addr = server.accept()
        hilo = threading.Thread(target=manejar_cliente, args=(conn, addr, rsa_key))
        hilo.start()
        print(f"[#] Clientes activos: {threading.active_count()-1}")
