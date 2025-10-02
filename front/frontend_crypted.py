# frontend_crypted_bytes.py
import socket
import threading
import json
import queue
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import crypto

HOST = "192.168.20.71"
PORT = 5000

LIGHT_THEME = {"bg": "white", "fg": "black", "entry_bg": "white", "entry_fg": "black", "text_bg": "white", "text_fg": "black"}
DARK_THEME = {"bg": "#2b2b2b", "fg": "white", "entry_bg": "#3c3f41", "entry_fg": "white", "text_bg": "#3c3f41", "text_fg": "white"}

class ChatClientGUI:
    def __init__(self, master, host, port):
        self.master = master
        self.host = host
        self.port = port
        self.sock = None
        self.recv_queue = queue.Queue()
        self.username = None
        self.aes_key = None
        self.rsa_key = crypto.generate_rsa_keypair()
        self.build_ui()
        self.connect_to_server()
        self.master.after(100, self.process_recv_queue)

    def build_ui(self):
        self.master.title("Chat cliente")
        self.master.geometry("900x550")
        self.text = scrolledtext.ScrolledText(self.master, state="disabled", width=70, height=25)
        self.text.grid(row=0, column=0, columnspan=3, padx=10, pady=10)
        self.entry = tk.Entry(self.master, width=55)
        self.entry.grid(row=1, column=0, padx=10, sticky="w")
        self.entry.bind("<Return>", lambda e: self.on_send_clicked())
        self.send_btn = tk.Button(self.master, text="Enviar", width=10, command=self.on_send_clicked)
        self.send_btn.grid(row=1, column=1, padx=(0, 10), sticky="w")
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    # -------------------- Conexión y handshake --------------------
    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
        except Exception as e:
            messagebox.showerror("Error", f"No se puede conectar al servidor: {e}")
            return

        if not self.handshake_seguro_cliente():
            messagebox.showerror("Error", "Handshake fallido")
            self.sock.close()
            return

        self.ask_and_send_alias()
        threading.Thread(target=self.receiver_loop, daemon=True).start()
        self.display_local("[Conectado al servidor de manera segura...]")

    def handshake_seguro_cliente(self):
        try:
            # 1) Recibir clave pública del servidor
            server_pub_pem = self.sock.recv(4096)
            server_pub = crypto.RSA.import_key(server_pub_pem)

            # 2) Generar clave AES
            self.aes_key = crypto.get_random_bytes_safe(32)

            # 3) Enviar AES cifrada
            enc_aes = crypto.rsa_encrypt_with_pub_pem(server_pub_pem, self.aes_key)
            self.sock.sendall(enc_aes)

            # 4) Recibir OTP cifrada
            otp_enc = self.sock.recv(4096)
            otp_plain = crypto.aes_gcm_decrypt(self.aes_key, otp_enc)

            # 5) Reenviar OTP como confirmación
            self.sock.sendall(crypto.aes_gcm_encrypt(self.aes_key, otp_plain))

            # 6) Recibir confirmación final
            result_enc = self.sock.recv(4096)
            result = crypto.aes_gcm_decrypt(self.aes_key, result_enc).decode()
            return result == "OTP_OK"

        except Exception as e:
            self.display_local(f"[x] Error handshake cliente: {e}")
            return False

    # -------------------- Recepción --------------------
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
                    raw_msg = json.loads(buffer.decode())
                    # Descifrar contenido si existe
                    if raw_msg.get("type") == "MSG" and "content" in raw_msg:
                        try:
                            raw_msg["content"] = crypto.decrypt_from(self.sock, raw_msg["content"])
                        except:
                            raw_msg["content"] = "[Error al descifrar]"
                    self.recv_queue.put(raw_msg)
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
            if t in ["MSG", "INFO", "ERROR", "DISCONNECTED"]:
                self.display_local(f"[{t}] {msg.get('content','')}")
        self.master.after(100, self.process_recv_queue)

    # -------------------- Envío --------------------
    def ask_and_send_alias(self):
        alias = simpledialog.askstring("Alias", "Ingresa tu alias:", parent=self.master)
        if not alias:
            alias = f"User{threading.get_ident()%1000}"
        self.username = alias.strip()
        msg = {"type": "ALIAS", "alias": self.username}
        enc = crypto.encrypt_for(self.sock, json.dumps(msg))
        self.sock.sendall(enc)

    def send_json(self, obj):
        try:
            enc = crypto.encrypt_for(self.sock, json.dumps(obj))
            payload = {"type": "MSG", "content": enc}
            self.sock.sendall(json.dumps(payload).encode())
        except Exception as e:
            self.display_local(f"[x] Error al enviar: {e}")

    def on_send_clicked(self):
        txt = self.entry.get().strip()
        if not txt:
            return
        self.send_json({"type": "MSG", "content": txt})
        self.display_local(f"{self.username}: {txt}")
        self.entry.delete(0, tk.END)

    # -------------------- UI --------------------
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


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root, HOST, PORT)
    root.mainloop()
