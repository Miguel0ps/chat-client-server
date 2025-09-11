import socket
import threading
from handlers import manejar_cliente

def iniciar_servidor(HOST="192.168.20.71", PORT=5000, MAX_CLIENTES=5):
    """Arranca el servidor y acepta conexiones"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(MAX_CLIENTES)


    print(f"Servidor escuchando en {HOST}:{PORT} (máx {MAX_CLIENTES} clientes)...")

    while True:
        conn, addr = server.accept()
        hilo = threading.Thread(target=manejar_cliente, args=(conn, addr))
        hilo.start()
        C = threading.active_count()-1
        print(f"[#] Clientes activos: {C}") #Muestra los clientes activos en el servidor
