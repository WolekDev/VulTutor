#!/usr/bin/env python3

import os
import sqlite3
from pathlib import Path
import tkinter as tk
from tkinter import messagebox

DB_FILENAME = "sqli_users.db"

def get_db_path():
    return Path(__file__).parent.joinpath(DB_FILENAME)

def init_db():
    db_path = get_db_path()
    if db_path.exists(): 
        return
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)")
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", "supermegasecretdontusethistogettheflagplz"))
    conn.commit()
    conn.close()

def attempt_login(username: str, password: str):
    db_path = get_db_path()
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    query = "SELECT id FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    try:
        c.execute(query)
        row = c.fetchone()
    except Exception as e:
        conn.close()
        return False, f"Error: {e}"
    conn.close()
    if row:
        return True, "Login as admin successful!\nFlag: sqli_bypass_success"
    return False, "Login failed: Username or password is incorrect."

def build_gui():
    root = tk.Tk()
    root.title("HGA SSO LOGIN")
    tk.Label(root, text="HGA SSO", font=("Default", 32, "bold", "italic"), fg="blue").grid(row=0, column=0, columnspan=2, pady=(12, 6))
    tk.Label(root, text="Welcome to HGA SSO Login", font=("Default", 16, "bold")).grid(row=1, column=0, columnspan=2, pady=(12, 6))
    tk.Label(root, text="Username:").grid(row=2, column=0, padx=6, pady=6)
    user_entry = tk.Entry(root, width=40)
    user_entry.grid(row=2, column=1, padx=6, pady=6)
    tk.Label(root, text="Password:").grid(row=3, column=0, padx=6, pady=6)
    pass_entry = tk.Entry(root, show="*", width=40)
    pass_entry.grid(row=3, column=1, padx=6, pady=6)
    def on_login():
        username = user_entry.get()
        password = pass_entry.get()
        success, message = attempt_login(username, password)
        if success:
            messagebox.showinfo("Result", message)
        else:
            messagebox.showerror("Result", message)
    login_btn = tk.Button(root, text="Login", command=on_login)
    login_btn.grid(row=4, column=0, columnspan=2, pady=(6, 12))
    root.resizable(False, False)
    return root

def main():
    init_db()
    root = build_gui()
    root.mainloop()

if __name__ == "__main__":
    main()
