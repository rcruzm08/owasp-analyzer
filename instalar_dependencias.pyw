import os
import sys
import subprocess
import tkinter as tk
from tkinter import messagebox
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)

root = tk.Tk()
root.withdraw()

try:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=BASE_DIR)
    messagebox.showinfo("OWASP Analyzer", "Dependências instaladas com sucesso.")
except Exception as exc:
    messagebox.showerror("OWASP Analyzer", f"Erro ao instalar dependências:\n{exc}")
