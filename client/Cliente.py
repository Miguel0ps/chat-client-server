import socket
from security import rsa_cifrar, aes_cifrar, aes_descifrar

HOST = "127.0.0.1"
PORT = 5000

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # 1. Recibir clave pública
    public_key = s.recv(4096)

    # 2. Generar clave AES y mandarla cifrada
    from security import generar_clave_aes
    aes_key = generar_clave_aes()
    s.sendall(rsa_cifrar(public_key, aes_key))

    # 3. OTP challenge
    otp_challenge_enc = s.recv(4096).decode("utf-8")
    otp_challenge = aes_descifrar(aes_key, otp_challenge_enc)
    print("[OTP recibido]", otp_challenge)

    # 4. Responder OTP
    s.sendall(aes_cifrar(aes_key, otp_challenge).encode("utf-8"))

    # 5. Confirmación
    confirm = s.recv(4096).decode("utf-8")
    if aes_descifrar(aes_key, confirm) != "OK":
        print("❌ Falló autenticación")
        s.close()
        return
    print("✅ Sesión segura establecida")

    # Chat loop
    while True:
        msg = input("Mensaje: ")
        s.sendall(aes_cifrar(aes_key, msg).encode("utf-8"))
        resp = s.recv(4096).decode("utf-8")
        print(">>", aes_descifrar(aes_key, resp))

if __name__ == "__main__":
    main()
