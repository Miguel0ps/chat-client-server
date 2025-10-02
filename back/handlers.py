# handlers.py
import json
import threading
from rooms import clientes, salas, unir_a_sala, crear_sala_privada, salir_sala
import crypto

def alias_disponible(nombre: str) -> bool:
    return all(info["alias"] != nombre for info in clientes.values())

def handshake_seguro(conn, rsa_key) -> bool:
    """Handshake RSA + AES + OTP"""
    try:
        # Enviar clave pública del servidor
        pub_pem = crypto.rsa_pub_pem(rsa_key)
        conn.sendall(pub_pem)

        # Recibir clave AES cifrada
        enc_aes = conn.recv(4096)
        aes_key = crypto.rsa_decrypt_with_key(rsa_key, enc_aes)
        crypto.set_session_aes(conn, aes_key)

        # OTP challenge
        otp = crypto.create_otp_for(conn)
        conn.sendall(crypto.encrypt_for(conn, otp).encode())

        # Recibir respuesta OTP
        resp_enc = conn.recv(4096).decode()
        resp = crypto.decrypt_from(conn, resp_enc)
        if not crypto.verify_otp_for(conn, resp):
            conn.sendall(crypto.encrypt_for(conn, "OTP_FAIL").encode())
            crypto.clear_session(conn)
            return False

        conn.sendall(crypto.encrypt_for(conn, "OTP_OK").encode())
        return True

    except Exception as e:
        print(f"[x] Error en handshake: {e}")
        crypto.clear_session(conn)
        return False

def pedir_alias(conn) -> str:
    """Solicita alias cifrado"""
    try:
        conn.sendall(crypto.encrypt_for(conn, json.dumps({
            "type": "ALIAS_REQUEST",
            "content": "Ingresa tu alias:"
        })).encode())

        data = conn.recv(4096).decode()
        msg = json.loads(crypto.decrypt_from(conn, data))

        alias = msg.get("alias", "")
        if not alias.strip():
            alias = f"User{threading.get_ident() % 1000}"

        return alias.strip()
    except Exception as e:
        print(f"[x] Error al recibir alias: {e}")
        return f"User{threading.get_ident() % 1000}"

def procesar_mensaje(conn, mensaje: dict):
    alias = clientes[conn]["alias"]
    sala = clientes[conn]["sala"]

    if mensaje["type"] == "MSG":
        contenido = crypto.decrypt_from(conn, mensaje.get("content", ""))
        for c in salas[sala]:
            if c != conn:
                enc_msg = crypto.encrypt_for(c, json.dumps({
                    "type": "MSG",
                    "content": f"{alias}: {contenido}"
                }))
                c.sendall(enc_msg.encode())

    elif mensaje["type"] == "PRIVATE":
        objetivo = mensaje.get("to")
        if objetivo == alias:
            return
        for c, info in clientes.items():
            if info["alias"] == objetivo:
                nueva_sala = crear_sala_privada(conn, c)
                aviso = f"Sala privada creada entre {alias} y {objetivo}"
                for x in salas[nueva_sala]:
                    x.sendall(crypto.encrypt_for(x, json.dumps({
                        "type": "INFO",
                        "content": aviso
                    })).encode())
                return
        conn.sendall(crypto.encrypt_for(conn, json.dumps({
            "type": "ERROR",
            "content": f"Usuario '{objetivo}' no encontrado."
        })).encode())

    elif mensaje["type"] == "LIST":
        lista_usuarios = [info["alias"] for info in clientes.values()]
        conn.sendall(crypto.encrypt_for(conn, json.dumps({
            "type": "LIST",
            "users": lista_usuarios
        })).encode())

    elif mensaje["type"] == "LEAVE_PRIVATE":
        sala_actual = clientes[conn]["sala"]
        if sala_actual != "general":
            if sala_actual in salas and conn in salas[sala_actual]:
                salas[sala_actual].remove(conn)
                if not salas[sala_actual]:
                    del salas[sala_actual]
            unir_a_sala(conn, "general")
            conn.sendall(crypto.encrypt_for(conn, json.dumps({
                "type": "INFO",
                "content": "Has vuelto al chat general."
            })).encode())

def manejar_cliente(conn, addr, rsa_key):
    """Función principal para manejar a un cliente"""
    print(f"[+] Nueva conexión desde {addr}")

    if not handshake_seguro(conn, rsa_key):
        print(f"[x] Handshake fallido con {addr}")
        conn.close()
        return

    alias = pedir_alias(conn)
    clientes[conn] = {"alias": alias, "sala": "general"}
    unir_a_sala(conn, "general")

    print(f"[+] {addr} identificado como {alias}")

    # Informar unión
    try:
        conn.sendall(crypto.encrypt_for(conn, json.dumps({
            "type": "INFO",
            "content": f"{alias} te has unido al chat General."
        })).encode())

        for c in salas["general"]:
            if c != conn:
                c.sendall(crypto.encrypt_for(c, json.dumps({
                    "type": "INFO",
                    "content": f"{alias} se ha unido al chat."
                })).encode())
    except Exception as e:
        print(f"[x] Error notificando unión de {alias}: {e}")

    # Loop de mensajes
    try:
        while True:
            data = conn.recv(4096).decode()
            if not data:
                break
            try:
                mensaje = json.loads(crypto.decrypt_from(conn, data))
            except Exception as e:
                conn.sendall(crypto.encrypt_for(conn, json.dumps({
                    "type": "ERROR",
                    "content": f"JSON inválido ({e})"
                })).encode())
                continue

            procesar_mensaje(conn, mensaje)

    except Exception as e:
        print(f"[x] Error con {alias}: {e}")

    finally:
        if conn in clientes:
            salir_sala(conn)
            for c in salas.get("general", []):
                if c != conn:
                    c.sendall(crypto.encrypt_for(c, json.dumps({
                        "type": "INFO",
                        "content": f"{alias} se ha salido del chat."
                    })).encode())
            del clientes[conn]

        crypto.clear_session(conn)
        print(f"[-] Conexión cerrada con {alias}")
        conn.close()
