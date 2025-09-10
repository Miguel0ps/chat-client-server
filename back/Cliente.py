import socket
import threading

def recibir(sock):
    """Hilo que escucha al servidor en todo momento"""
    while True:
        try:
            data = sock.recv(1024).decode("utf-8")
            if data:
                print("\n" + data + "\n> ", end="")
        except:
            print("[x] Conexión cerrada por el servidor")
            break

# Configuración del cliente
HOST = "192.168.80.18"  # IP del servidor
PORT = 5000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

print("Conectado al chat. Escribe tus mensajes:")

# Lanzamos un hilo separado SOLO para escuchar al servidor
hilo_receptor = threading.Thread(target=recibir, args=(sock,))
hilo_receptor.start()

# Bucle para enviar mensajes
while True:
    msg = input("> ")
    if msg.lower() == "salir":
        sock.close()
        break
    sock.sendall(msg.encode("utf-8"))