# main.py server
from server import iniciar_servidor

if __name__ == "__main__":
    # Cambia la IP por la de tu servidor
    iniciar_servidor(HOST="192.168.20.71", PORT=5000)
