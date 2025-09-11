import socket
import json
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

alias = input("Ingrese un alias permitido: ")

EnvioAlias = {"type": "ALIAS", "alias": alias}

# Lanzamos un hilo separado SOLO para escuchar al servidor
hilo_receptor = threading.Thread(target=recibir, args=(sock,))
hilo_receptor.start()

sock.sendall(json.dumps(EnvioAlias).encode('utf-8'))

# Bucle para enviar mensajes o comandos
while True:
    msg = input("")
    if msg.lower() == "salir":
        sock.close()
        break
    elif msg.lower() == "lista":
        lista = {"type":"LIST"}
        sock.sendall(json.dumps(lista).encode('utf-8'))

    elif msg.lower() == "priv":
        objetivo = input("Alias del sujeto con quien hablar en privado\n:")
        Privado = {"type": "PRIVATE", "to":objetivo}
        sock.sendall(json.dumps(Privado).encode('utf-8'))

    elif msg.lower() == "general":
        General = {"type": "EXIT"}
        sock.sendall(json.dumps(General).encode('utf-8')) 
    
    else:
        mensaje = {"type": "MSG", "content": msg}

        sock.sendall(json.dumps(mensaje).encode('utf-8'))
    
