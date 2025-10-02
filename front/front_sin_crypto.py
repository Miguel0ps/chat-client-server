import socket
import threading
import json
import queue
import re
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext

HOST = "192.168.1.11"   # Cambia a tu IP
PORT = 5000

# --- Temas de color ---
LIGHT_THEME = {
    "bg": "white",
    "fg": "black",
    "entry_bg": "white",
    "entry_fg": "black",
    "text_bg": "white",
    "text_fg": "black"
}

DARK_THEME = {
    "bg": "#2b2b2b",
    "fg": "white",
    "entry_bg": "#3c3f41",
    "entry_fg": "white",
    "text_bg": "#3c3f41",
    "text_fg": "white"
}


class PrivateWindow:
    def __init__(self, master, client_app, other_alias):
        self.client_app = client_app
        self.other = other_alias
        self.top = tk.Toplevel(master)
        self.top.title(f"Privado: {client_app.username or '??'} ↔ {self.other}")
        self.top.protocol("WM_DELETE_WINDOW", self.on_close)

        self.text = scrolledtext.ScrolledText(self.top, state="disabled", width=60, height=20)
        self.text.pack(padx=8, pady=6)

        frm = tk.Frame(self.top)
        frm.pack(padx=8, pady=(0, 8), fill="x")

        self.entry = tk.Entry(frm, width=48)
        self.entry.pack(side="left", expand=True, fill="x")
        self.entry.bind("<Return>", lambda ev: self.on_send())

        self.send_btn = tk.Button(frm, text="Enviar", command=self.on_send)
        self.send_btn.pack(side="left", padx=(6, 0))

    def display(self, msg):
        self.text.config(state="normal")
        self.text.insert(tk.END, msg + "\n")
        self.text.config(state="disabled")
        self.text.see(tk.END)

    def on_send(self):
        txt = self.entry.get().strip()
        if not txt:
            return
        
        content_to_send = f"(privado) {txt}"
        payload = {"type": "MSG", "content": content_to_send}
        self.client_app.send_json(payload)

        content_to_display = f"{self.client_app.username}: {content_to_send}"
        self.display(content_to_display)
        
        self.entry.delete(0, tk.END)

    def on_close(self):
        # ------------------- NUEVO CÓDIGO AÑADIDO -------------------
        # Antes de cerrar la ventana, enviamos el comando al servidor
        # para que nos devuelva al chat general.
        self.client_app.send_json({"type": "LEAVE_PRIVATE"})
        # ------------------- FIN DEL CÓDIGO AÑADIDO -------------------

        self.top.destroy()
        if self.other in self.client_app.private_windows:
            del self.client_app.private_windows[self.other]


class ChatClientGUI:
    def __init__(self, master, host, port):
        self.master = master
        self.host = host
        self.port = port

        self.sock = None
        self.recv_thread = None
        self.recv_queue = queue.Queue()

        self.username = None
        self.private_windows = {}

        self.theme = LIGHT_THEME
        self.build_ui()
        self.apply_theme()
        self.connect_to_server()

    def build_ui(self):
        self.master.title("Chat cliente")
        self.master.geometry("900x550")

        # Mensajes (área principal)
        self.text = scrolledtext.ScrolledText(self.master, state="disabled", width=70, height=25)
        self.text.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

        # Entry y botones
        self.entry = tk.Entry(self.master, width=55)
        self.entry.grid(row=1, column=0, padx=10, sticky="w")
        self.entry.bind("<Return>", lambda e: self.on_send_clicked())

        self.send_btn = tk.Button(self.master, text="Enviar", width=10, command=self.on_send_clicked)
        self.send_btn.grid(row=1, column=1, padx=(0, 10), sticky="w")

        # Botón emojis
        self.emoji_btn = tk.Button(self.master, text="😀", command=self.show_emojis)
        self.emoji_btn.grid(row=1, column=2, sticky="w")

        # Lista de usuarios
        lbl = tk.Label(self.master, text="Usuarios conectados:")
        lbl.grid(row=0, column=3, padx=6, sticky="n")

        self.users_list = tk.Listbox(self.master, width=25, height=25)
        self.users_list.grid(row=0, column=3, padx=6, pady=(20, 0), sticky="n")

        # Botones extra
        self.priv_btn = tk.Button(self.master, text="Chat privado", width=18, command=self.open_private_for_selected)
        self.priv_btn.grid(row=1, column=3, padx=6, pady=(6, 0), sticky="n")

        self.ls_btn = tk.Button(self.master, text="Actualizar usuarios", command=self.request_list)
        self.ls_btn.grid(row=2, column=3, padx=6, pady=(6, 0), sticky="n")

        self.theme_btn = tk.Button(self.master, text="🌙 Modo oscuro", command=self.toggle_theme)
        self.theme_btn.grid(row=3, column=3, padx=6, pady=(6, 0), sticky="n")

        # Grid flexible
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)

        self.master.after(100, self.process_recv_queue)
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    # ------------------- Funciones de red -------------------
    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
        except Exception as e:
            messagebox.showerror("Error", f"No se puede conectar al servidor {self.host}:{self.port}\n{e}")
            return

        self.recv_thread = threading.Thread(target=self.receiver_loop, daemon=True)
        self.recv_thread.start()
        self.display_local("[Conectado al servidor...]")

    def receiver_loop(self):
        buffer = b""
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    self.recv_queue.put({"type": "DISCONNECTED", "content": "Conexión cerrada por servidor"})
                    break
                buffer += data
                try:
                    text = buffer.decode('utf-8').strip()
                    if not text or text.startswith("-"):
                        buffer = b""
                        continue
                    msg = json.loads(text)
                    self.recv_queue.put(msg)
                    buffer = b""
                except json.JSONDecodeError:
                    continue
            except Exception as e:
                self.recv_queue.put({"type": "DISCONNECTED", "content": str(e)})
                break

    def process_recv_queue(self):
        while not self.recv_queue.empty():
            msg = self.recv_queue.get()
            t = msg.get("type")
            if t == "ALIAS_REQUEST":
                self.ask_and_send_alias()
            elif t == "MSG":
                content = msg.get("content", "")
                if "(privado)" in content:
                    m = re.match(r"([^:]+):\s+\(privado\)\s+(.*)", content)
                    if m:
                        sender = m.group(1).strip()
                        private_msg = m.group(2).strip()

                        if sender not in self.private_windows:
                            self.open_private_window(sender)

                        self.private_windows[sender].display(f"{sender} (privado): {private_msg}")
                else:
                    self.display_local(content)
            elif t == "INFO":
                content = msg.get("content", "")
                self.display_local("[INFO] " + content)

                if "Sala privada creada" in content:
                    partes = re.findall(r"entre\s+(\w+)\s+y\s+(\w+)", content)
                    if partes:
                        a, b = partes[0]
                        if self.username == a:
                            other = b
                        elif self.username == b:
                            other = a
                        else:
                            other = None

                        if other and other not in self.private_windows:
                            self.open_private_window(other)
            elif t == "ERROR":
                self.display_local("[ERROR] " + msg.get("content", ""))
            elif t == "LIST":
                users = msg.get("users", [])
                self.update_userlist(users)
            elif t == "DISCONNECTED":
                self.display_local("[DESC] " + msg.get("content", "Desconectado"))
                try:
                    self.sock.close()
                except:
                    pass
            else:
                self.display_local(str(msg))

        self.master.after(100, self.process_recv_queue)

    def ask_and_send_alias(self):
        alias = simpledialog.askstring("Alias", "Ingresa tu alias:", parent=self.master)
        if not alias or not alias.strip():
            alias = f"User{threading.get_ident() % 1000}"
        self.username = alias.strip()
        try:
            payload = {"type": "ALIAS", "alias": self.username}
            self.sock.sendall(json.dumps(payload).encode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo enviar el alias: {e}")
        self.request_list()

    def send_json(self, obj):
        try:
            self.sock.sendall(json.dumps(obj).encode('utf-8'))
        except Exception as e:
            self.display_local(f"[x] Error al enviar: {e}")

    def request_list(self):
        self.send_json({"type": "LIST"})

    # ------------------- UI acciones -------------------
    def on_send_clicked(self):
        txt = self.entry.get().strip()
        if not txt:
            return
        self.send_msg(txt)
        self.display_local(f"{self.username}: {txt}")
        self.entry.delete(0, tk.END)

    def send_msg(self, content):
        self.send_json({"type": "MSG", "content": content})

    def open_private_for_selected(self):
        sel = self.users_list.curselection()
        if not sel:
            messagebox.showwarning("Atención", "Selecciona un usuario para crear la sala privada")
            return
        target = self.users_list.get(sel)
        if target == self.username:
            messagebox.showinfo("Info", "No puedes abrir sala privada contigo mismo")
            return
        
        self.send_json({"type": "PRIVATE", "to": target})

        if target not in self.private_windows:
            self.open_private_window(target)

    def open_private_window(self, other_alias):
        if other_alias in self.private_windows:
            self.private_windows[other_alias].top.lift()
            return
        w = PrivateWindow(self.master, self, other_alias)
        self.private_windows[other_alias] = w

    def update_userlist(self, users):
        self.users_list.delete(0, tk.END)
        for u in users:
            self.users_list.insert(tk.END, u)

    def display_local(self, msg):
        self.text.config(state="normal")
        self.text.insert(tk.END, msg + "\n")
        self.text.config(state="disabled")
        self.text.see(tk.END)

    def on_close(self):
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        self.master.destroy()

    # ------------------- Tema oscuro / emojis -------------------
    def toggle_theme(self):
        if self.theme == LIGHT_THEME:
            self.theme = DARK_THEME
            self.theme_btn.config(text="☀️ Modo claro")
        else:
            self.theme = LIGHT_THEME
            self.theme_btn.config(text="🌙 Modo oscuro")
        self.apply_theme()

    def apply_theme(self):
        t = self.theme
        self.master.configure(bg=t["bg"])
        try:
            self.text.config(bg=t["text_bg"], fg=t["text_fg"])
            self.entry.config(bg=t["entry_bg"], fg=t["entry_fg"], insertbackground=t["fg"])
            self.users_list.config(bg=t["entry_bg"], fg=t["entry_fg"])
        except:
            pass

    def show_emojis(self):
        menu = tk.Menu(self.master, tearoff=0)
        emojis = ["😀", "😭", "😂", "🥺", "😍", "😎", "😢", "👍", "🔥", "❤️"]
        for e in emojis:
            menu.add_command(label=e, command=lambda em=e: self.insert_emoji(em))
        try:
            menu.tk_popup(self.emoji_btn.winfo_rootx(), self.emoji_btn.winfo_rooty() + 30)
        finally:
            menu.grab_release()

    def insert_emoji(self, emoji):
        self.entry.insert(tk.END, emoji)


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root, HOST, PORT)
    root.mainloop()