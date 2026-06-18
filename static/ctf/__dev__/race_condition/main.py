#!/usr/bin/env python3

import tkinter as tk
from tkinter import messagebox
import threading
import time

balance   = 10
controllers_bought = 0

ITEM_NAME  = "Game Controller"
ITEM_PRICE = 10

def process_purchase(collector_name: str, tab_id: int, log_callback, done_callback):
    global balance, controllers_bought
    log_callback(tab_id, f"[1] Balance check: {balance} zl (need {ITEM_PRICE} zl) - OK")
    if balance < ITEM_PRICE:
        log_callback(tab_id, f"[1] Balance check: {balance} zl (need {ITEM_PRICE} zl) - DENIED Insufficient funds")
        done_callback(tab_id)
        return
    delay = max(0.4, min(len(collector_name) * 0.07, 4.0))
    log_callback(tab_id, f"[2] Writing '{collector_name}' to DB (~{delay:.1f}s) - please wait...")
    time.sleep(delay)
    log_callback(tab_id, f"[2] DB write complete.")
    balance = (balance - ITEM_PRICE)
    controllers_bought += 1
    log_callback(tab_id, f"[3] Deducted {ITEM_PRICE} zl. New balance: {balance} zl")
    done_callback(tab_id)

# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

def main():
    root = tk.Tk()
    root.title("OSMA Hardware Store")
    root.resizable(False, False)
    tk.Label(root, text="🔧 OSMA Hardware Store", font=("Default", 15, "bold"), fg="orange").grid(row=0, column=0, columnspan=2, pady=(14, 2))
    tk.Label(root, text="Online Portal", font=("Default", 9), fg="grey").grid(row=1, column=0, columnspan=2, pady=(0, 8))
    balance_var = tk.StringVar(value=f"Store Credit: {balance} zl")
    tk.Label(root, textvariable=balance_var, font=("Default", 12, "bold"), fg="green").grid(row=2, column=0, columnspan=2, pady=(0, 10))
    tab_frames   = []
    name_vars    = []
    log_texts    = []
    buy_buttons  = []
    status_vars  = []
    ACCOUNT_ID = "ACC-00042"
    def refresh_balance():
        balance_var.set(f"Store Credit: {balance} zl")
    def append_log(tab_id: int, msg: str):
        root.after(0, lambda: append_log_ui(tab_id, msg))
    def append_log_ui(tab_id: int, msg: str):
        txt = log_texts[tab_id]
        txt.config(state="normal")
        txt.insert("end", msg + "\n")
        txt.see("end")
        txt.config(state="disabled")
        refresh_balance()
    def on_done(tab_id: int):
        root.after(0, lambda: on_done_ui(tab_id))
    def on_done_ui(tab_id: int):
        buy_buttons[tab_id].config(state="normal")
        status_vars[tab_id].set("Ready")
        refresh_balance()
        if controllers_bought >= 2:
            messagebox.showinfo(
                "!!!Congratulations!!!",
                "You purchased 2 Game Controllers!\n"
                "Congratulations on your free headphones!\n"
                "Flag: my_free_headphones"
            )

    def make_tab(col: int, label: str):
        tab_id = col
        frame = tk.LabelFrame(root, text=label, padx=14, pady=10)
        frame.grid(row=3, column=col, padx=10, pady=6, sticky="n")
        tab_frames.append(frame)
        tk.Label(frame, text="Account ID:").grid(row=0, column=0, sticky="e", pady=3)
        acc_entry = tk.Entry(frame, width=20)
        acc_entry.insert(0, ACCOUNT_ID)
        acc_entry.config(state="disabled", disabledforeground="#555")
        acc_entry.grid(row=0, column=1, padx=6, pady=3)
        tk.Label(frame, text="Your Name:").grid(row=1, column=0, sticky="e", pady=3)
        nv = tk.StringVar()
        name_vars.append(nv)
        tk.Entry(frame, textvariable=nv, width=20).grid(row=1, column=1, padx=6, pady=3)
        item_frame = tk.LabelFrame(frame, text="Item", padx=8, pady=6)
        item_frame.grid(row=2, column=0, columnspan=2, pady=8, sticky="ew")
        tk.Label(item_frame, text="🎮  Game Controller",font=("Default", 10, "bold")).pack()
        tk.Label(item_frame, text=f"{ITEM_PRICE} zl").pack()
        sv = tk.StringVar(value="Ready")
        status_vars.append(sv)
        def on_buy(tid=tab_id):
            name = name_vars[tid].get().strip()
            if not name:
                messagebox.showerror("Error", "Please enter your name.", parent=root)
                return
            buy_buttons[tid].config(state="disabled")
            status_vars[tid].set("Processing…")
            t = threading.Thread(target=process_purchase, args=(name, tid, append_log, on_done), daemon=True)
            t.start()
        btn = tk.Button(frame, text="🛒  Buy Controller", font=("Default", 10, "bold"), command=on_buy)
        btn.grid(row=3, column=0, columnspan=2, pady=(4, 2), ipadx=6, ipady=3)
        buy_buttons.append(btn)
        tk.Label(frame, textvariable=sv, font=("Courier", 8), fg="grey").grid(row=4, column=0, columnspan=2)
        tk.Label(frame, text="Transaction Log:", font=("Default", 8, "bold")).grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 0))
        txt = tk.Text(frame, width=38, height=9, font=("Courier", 7), state="disabled", bg="white")
        txt.grid(row=6, column=0, columnspan=2, pady=(2, 4))
        log_texts.append(txt)
    make_tab(0, "Tab 1")
    make_tab(1, "Tab 2")
    root.mainloop()

if __name__ == "__main__":
    main()