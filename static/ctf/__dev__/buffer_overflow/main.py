#!/usr/bin/env python3

import tkinter as tk
from tkinter import messagebox

count = 0
user_id = 5
products = []

def update_user_id(id):
    global user_id
    if count == 5:
        user_id = id
    if count > 5:
        print("Segmentation fault (core dumped)")
        exit(0)

def main():
    global products
    root = tk.Tk()
    root.title("Goodronka Self Checkout")
    tk.Label(root, text="Goodronka Self Checkout", font=("Default", 16, "bold", "italic"), fg="green").grid(row=0, column=1, columnspan=2, pady=(12, 6))
    products_frame = tk.LabelFrame(root, text="Products", pady=6)
    products_frame.grid(row=1, column=0, padx=6, pady=6)
    products_label = tk.Label(products_frame, text=f"Total: 0 zl")
    products_label.grid(row=0, column=0, padx=16, pady=6)
    tk.Label(root, text="Item ID:").grid(row=1, column=1, padx=2, pady=6)
    e = tk.Entry(root, width=30)
    e.grid(row=1, column=2, padx=6, pady=4)
    def on_submit():
        global count
        count += 1
        id = e.get().strip()
        try: 
            id = int(id)
            if id < 0:
                messagebox.showerror("Error", "Invalid ID, please enter a positive number.")
                return
        except Exception:
            messagebox.showerror("Error", "Invalid ID, please enter a number.")
            return
        update_user_id(id)
        products.append((id, (((id * 3 + 2) % 100) + 1)))
        products_label_text = ""
        for i in range(len(products)):
           products_label_text += f"ID {products[i][0]} \t {products[i][1]} zl\n"
        products_label_text += f"\nTotal: {sum([i[1] for i in products])} zl"
        products_label.config(text=products_label_text)
    def on_finish():
        global count
        global user_id
        global products
        if user_id == 0:
            messagebox.showinfo("ADMIN", f"User ID: {user_id}\nOpening ADMIN DASHBOARD ...\nFlag: admin_dashboard_access")
        else:
            messagebox.showinfo("Payment", f"User ID: {user_id}\nPayment amount: {sum([i[1] for i in products])} zl\nPayment successful!")
        products = []
        count = 0
        products_label.config(text=f"Total: {sum([i[1] for i in products])} zl")
    tk.Button(root, text="Submit", command=on_submit).grid(row=1, column=3, columnspan=2, pady=(8, 12))
    tk.Button(root, text="Finish", command=on_finish).grid(row=4, column=1, columnspan=2, pady=(8, 12))
    root.resizable(False, False)
    root.mainloop()

if __name__ == "__main__":
    main()
