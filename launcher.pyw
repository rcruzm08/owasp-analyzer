import os
import sys
import time
import threading
import webbrowser
import tkinter as tk
from tkinter import messagebox
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)
sys.path.insert(0, str(BASE_DIR))

URL = "http://127.0.0.1:5000"
server_started = False
server_error = None

def ensure_env():
    env_path = BASE_DIR / ".env"
    example_path = BASE_DIR / ".env.example"
    if not env_path.exists() and example_path.exists():
        env_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")


def run_server():
    global server_started, server_error
    try:
        ensure_env()
        from app import app
        server_started = True
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    except Exception as exc:
        server_error = str(exc)


def wait_and_open(root, label):
    for _ in range(20):
        if server_error:
            label.config(text="Erro ao iniciar o servidor.")
            messagebox.showerror("OWASP Analyzer", server_error)
            return
        if server_started:
            label.config(text="Servidor iniciado em http://127.0.0.1:5000")
            webbrowser.open(URL)
            return
        time.sleep(0.25)
    label.config(text="Servidor iniciado. Abra o navegador manualmente se necessário.")
    webbrowser.open(URL)


def open_browser():
    webbrowser.open(URL)


def close_app(root):
    root.destroy()
    os._exit(0)


def main():
    root = tk.Tk()
    root.title("OWASP Analyzer")
    root.geometry("460x230")
    root.resizable(False, False)

    frame = tk.Frame(root, padx=24, pady=24)
    frame.pack(fill="both", expand=True)

    title = tk.Label(frame, text="OWASP Code Analyzer", font=("Arial", 16, "bold"))
    title.pack(anchor="w")

    label = tk.Label(frame, text="Iniciando servidor local...", font=("Arial", 10), fg="#374151")
    label.pack(anchor="w", pady=(10, 18))

    info = tk.Label(
        frame,
        text="Use esta janela para manter o sistema ativo.\nFechar esta janela encerra o servidor local.",
        font=("Arial", 9),
        justify="left",
        fg="#4b5563"
    )
    info.pack(anchor="w", pady=(0, 18))

    buttons = tk.Frame(frame)
    buttons.pack(anchor="w")

    open_btn = tk.Button(buttons, text="Abrir no navegador", command=open_browser, width=18)
    open_btn.pack(side="left", padx=(0, 10))

    close_btn = tk.Button(buttons, text="Encerrar", command=lambda: close_app(root), width=12)
    close_btn.pack(side="left")

    threading.Thread(target=run_server, daemon=True).start()
    threading.Thread(target=wait_and_open, args=(root, label), daemon=True).start()

    root.protocol("WM_DELETE_WINDOW", lambda: close_app(root))
    root.mainloop()


if __name__ == "__main__":
    main()
