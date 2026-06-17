#!/usr/bin/env python3

import tkinter as tk
from tkinter import messagebox

def evaluate_price(price_val):
    try:
        price = int(price_val)
    except Exception:
        return False, "Invalid price, please enter a number."
    if price < 50:
        return False, "The store requires a minimum price of 50 zl."
    wrapped = price % 65536
    if wrapped == 0:
        return True, "!!!CONGRATULATION!!!\nFree Game Claimed\nFlag: yay_free_gta6"
    else: 
        return False, f"Payment amount: {wrapped} zl\nProcessing payment...\nInsufficient funds!!!"

def build_gui():
    root = tk.Tk()
    root.title("MAETS GAME STORE (No Scam Guarantee)")
    game_frame = tk.LabelFrame(root, text="", pady=20)
    game_frame.grid(row=0, column=0, columnspan=2, padx=12, pady=12)
    tk.Label(game_frame, text="GTA 6", font=("Default", 16, "bold", "italic"), fg="red").grid(row=0, column=0, padx=6, pady=6)
    tk.Label(game_frame, text="StoneStar Games").grid(row=1, column=0, padx=6, pady=6)
    tk.Label(game_frame, text="Totally Legit").grid(row=2, column=0, padx=6, pady=6)
    tk.Label(root, text="Good Thrift Auto 6").grid(row=1, column=0, columnspan=2, padx=6, pady=6)
    tk.Label(root, text="Release Date: 31/11/2026").grid(row=2, column=0, columnspan=2, padx=6, pady=6)
    tk.Label(root, text="Name your price (50 zl or more):").grid(row=3, column=0, padx=6, pady=6)
    price_entry = tk.Entry(root, width=30)
    price_entry.grid(row=3, column=1, padx=6, pady=6)
    def on_submit():
        val = price_entry.get().strip()
        ok, msg = evaluate_price(val)
        if ok:
            messagebox.showinfo("Result", msg)
        else:
            messagebox.showerror("Error", msg)
    submit = tk.Button(root, text="Submit", command=on_submit)
    submit.grid(row=4, column=0, columnspan=2, pady=(8, 12))
    root.resizable(False, False)
    return root

def main():
    root = build_gui()
    root.mainloop()

if __name__ == "__main__":
    main()
