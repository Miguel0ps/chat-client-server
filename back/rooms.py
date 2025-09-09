# rooms.py
clientes = {}  # {conn: {"alias": str, "sala": str}}
salas = {"general": set()}


def crear_sala_privada(cliente1, cliente2):
    """Crea una sala privada para dos clientes."""
    alias1 = clientes[cliente1]["alias"]
    alias2 = clientes[cliente2]["alias"]
    nombre_sala = f"priv_{alias1}_{alias2}"
    salas[nombre_sala] = {cliente1, cliente2}
    clientes[cliente1]["sala"] = nombre_sala
    clientes[cliente2]["sala"] = nombre_sala
    return nombre_sala


def unir_a_sala(cliente, nombre_sala="general"):
    """Agrega un cliente a una sala."""
    if nombre_sala not in salas:
        salas[nombre_sala] = set()
    salas[nombre_sala].add(cliente)
    clientes[cliente]["sala"] = nombre_sala


def salir_sala(cliente):
    """
    El cliente sale de su sala actual.
    Si era una sala privada, la destruye y devuelve a cualquier otro cliente a general.
    """
    sala = clientes[cliente]["sala"]

    if sala in salas and cliente in salas[sala]:
        salas[sala].remove(cliente)

        # Si era una sala privada y queda un cliente, lo devolvemos a general
        if sala != "general" and len(salas[sala]) == 1:
            for otro in salas[sala]:
                clientes[otro]["sala"] = "general"
                salas["general"].add(otro)
            del salas[sala]

        # Si era sala privada y quedó vacía, simplemente eliminarla
        elif sala != "general" and len(salas[sala]) == 0:
            del salas[sala]

    # Finalmente, siempre ponemos al cliente que se va en la general
    clientes[cliente]["sala"] = "general"
    salas["general"].add(cliente)


def broadcast(mensaje, sala, emisor=None):
    """Envía un mensaje a todos los clientes de la sala, excepto al emisor."""
    for cliente in list(salas.get(sala, [])):
        if cliente != emisor:
            try:
                cliente.sendall(mensaje.encode("utf-8"))
            except:
                # Eliminar cliente si falla
                salas[sala].remove(cliente)
                clientes.pop(cliente, None)
