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
        if objetivo == alias:
            return
        
        encontrado = False
        for c, info in clientes.items():
            if info["alias"] == objetivo:
                #IMPORTANTE MANOOOO ACA FUE
                # 1. Creamos la sala y guardamos su nuevo nombre.
                nombre_nueva_sala = crear_sala_privada(conn, c)
                encontrado = True
                
                # 2. Usamos el nombre de la NUEVA sala para enviar la confirmación.
                broadcast(json.dumps({"type": "INFO", "content": f" Sala privada creada entre {alias} y {objetivo}"}), nombre_nueva_sala)
                # --- FIN DE LA CORRECCIÓN ---
                break
        
        if not encontrado:
            conn.sendall(
                json.dumps({"type": "ERROR", "content": f"Usuario '{objetivo}' no encontrado."}).encode("utf-8")
            )
            
    elif mensaje["type"] == "LIST":
        lista_usuarios = [info["alias"] for info in clientes.values()]
        conn.sendall(
            json.dumps({"type": "LIST", "users": lista_usuarios}).encode("utf-8")
        )
# IMPORTANTE ACA TAMBIEN PARA CUANDO SE SALE DE LA SALA PRIAVDA MANO
    elif mensaje["type"] == "LEAVE_PRIVATE":
        sala_actual = clientes[conn]["sala"]
        if sala_actual != "general":
            if sala_actual in salas and conn in salas[sala_actual]:
                salas[sala_actual].remove(conn)
                if not salas[sala_actual]:
                    del salas[sala_actual]
            
            unir_a_sala(conn, "general")
            
            conn.sendall(json.dumps({"type": "INFO", "content": "Has vuelto al chat general."}).encode("utf-8"))

def manejar_cliente(conn, addr):
    print(f"[+] Nueva conexión desde {addr}")
    alias = pedir_alias(conn)
    clientes[conn] = {"alias": alias, "sala": "general"}
    unir_a_sala(conn, "general")

    print(f"[+] {addr} identificado como {alias}")

    conn.sendall(json.dumps({"type": "INFO", "content": f"{alias} te has unido al chat General."}).encode("utf-8"))
    broadcast(json.dumps({"type": "INFO", "content": f" {alias} se ha unido al chat."}), "general", conn)

    try:
        while True:
            data = conn.recv(1024).decode("utf-8")
            if not data:
                break
            print(f"[{addr}] => {data}")
            try:
                mensaje = json.loads(data)
            except json.JSONDecodeError:
                conn.sendall(
                    json.dumps({"type": "ERROR", "content": "JSON invalido"}).encode("utf-8")
                )
                continue
            respuesta = f"--------***--------"
            conn.sendall(respuesta.encode("utf-8"))
            procesar_mensaje(conn, mensaje)

    except Exception as e:
        print(f"[x] Error con {alias}: {e}")

    finally:
        if conn in clientes:
            
            salir_sala(conn)

            broadcast(json.dumps({"type": "INFO", "content": f" {alias} se ha salido del chat."}), "general", conn)
            del clientes[conn]
        
        print(f"[-] Conexión cerrada con {alias}")
        conn.close()
