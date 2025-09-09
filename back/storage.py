def guardar_archivo(nombre, contenido):
    with open("archivos/" + nombre, "wb") as f:
        f.write(contenido)
    print(f"[+] Archivo {nombre} guardado.")

def cargar_archivo(nombre):
    with open("archivos/" + nombre, "rb") as f:
        return f.read()
