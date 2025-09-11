import json
from rooms import clientes, salas, unir_a_sala, crear_sala_privada, salir_sala, broadcast

def alias_disponible(nombre: str) -> bool:
    """Verifica si el alias ya está en uso."""
    return all(info["alias"] != nombre for info in clientes.values())


def pedir_alias(conn) -> str:
    """Solicita un alias único al cliente mediante JSON."""
    while True:
        conn.sendall(json.dumps({"type": "ALIAS_REQUEST"}).encode("utf-8"))
        data = conn.recv(1024).decode("utf-8")

        try:
            mensaje = json.loads(data)
        except json.JSONDecodeError:
            continue

        if mensaje.get("type") == "ALIAS":
            alias = mensaje.get("alias", "").strip()
            if not alias:
                alias = f"Cliente{len(clientes)+1}"
                return alias
            if alias_disponible(alias):
                return alias
            else:
                conn.sendall(
                    json.dumps({"type": "ERROR", "content": f"Alias '{alias}' en uso."}).encode("utf-8")
                )


def procesar_mensaje(conn, mensaje: dict):
    alias = clientes[conn]["alias"]
    sala = clientes[conn]["sala"]

    if mensaje["type"] == "MSG":
        contenido = mensaje.get("content", "") 
        broadcast(json.dumps({"type": "MSG", "content": f"{alias}: {contenido}"}), sala, conn) 

    elif mensaje["type"] == "PRIVATE":
        objetivo = mensaje.get("to")
        for c, info in clientes.items():
            if info["alias"] == objetivo:
                sala_privada = crear_sala_privada(conn, c)
                broadcast(
                    json.dumps({"type": "INFO", "content": f" Sala privada creada entre {alias} y {objetivo}"}),
                    sala_privada
                )
                return
        conn.sendall(
            json.dumps({"type": "ERROR", "content": "Usuario no encontrado"}).encode("utf-8")
        )

    elif mensaje["type"] == "EXIT":

        broadcast(json.dumps({"type": "INFO", "content": f" {alias} se ha salido del chat privado.\nAhora estas en el chat General"}), "general", conn) #Avisa al otro usaurio que con el que estaba hablando se devolvio al chat general junto con el 

        salir_sala(conn)
        conn.sendall(
            json.dumps({"type": "INFO", "content": "Has vuelto a la sala general."}).encode("utf-8") 
        )

    elif mensaje["type"] == "LIST":
        usuarios = [info["alias"] for info in clientes.values()]
        conn.sendall(json.dumps({"type": "LIST", "users": usuarios}).encode("utf-8"))

    else:
        conn.sendall(
            json.dumps({"type": "ERROR", "content": "Comando no reconocido"}).encode("utf-8")
        )


def manejar_cliente(conn, addr):
    print(f"[+] Conexión desde {addr}")

    # pedir alias
    alias = pedir_alias(conn)
    clientes[conn] = {"alias": alias, "sala": "general"}
    unir_a_sala(conn, "general")

    print(f"[+] {addr} identificado como {alias}")

    conn.sendall(json.dumps({"type": "INFO", "content": f"{alias} te has unido al chat General."}).encode("utf-8")) #Avisa al usuario que se ha unido al chat general
    broadcast(json.dumps({"type": "INFO", "content": f" {alias} se ha unido al chat."}), "general", conn)

    try:
        while True:
            data = conn.recv(1024).decode("utf-8")
            if not data:
                break
            print(f"[{addr}] => {data}") #muestra toda la informacion de los chats en el servidor 
            try:
                mensaje = json.loads(data)
            except json.JSONDecodeError:
                conn.sendall(
                    json.dumps({"type": "ERROR", "content": "JSON invalido"}).encode("utf-8")
                )
                continue
            respuesta = f"--------***--------"
            conn.sendall(respuesta.encode("utf-8")) #Respuesta del servidor par evitar que los clietnes esperen si llegan a estar solos
            procesar_mensaje(conn, mensaje)

    except Exception as e:
        print(f"[x] Error con {alias}: {e}")

    finally:
        if conn in clientes:
            
            salir_sala(conn)

            broadcast(json.dumps({"type": "INFO", "content": f" {alias} se ha salido del chat."}), "general", conn) #Avisa a los demas que se ha salido x usuario
            
            print(f"[-] {alias} se desconectó")
