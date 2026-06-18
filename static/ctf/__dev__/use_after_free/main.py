import tkinter as tk
from tkinter import messagebox

class SimulatedHeap:
    def __init__(self):
        self.blocks = {}           # Maps hex memory address -> string data
        self.free_list = []        # Tracks freed memory addresses (acting as a LIFO stack)
        self.next_address = 0x1000 # Simulating virtual memory boundaries
        self.note_to_address = {}  # Dangling pointer table: maps Note ID -> address

    def allocate(self, note_id, default_data=""):
        if self.free_list:
            # Grab from the END of the list (LIFO). 
            # This returns the most recently freed memory address.
            address = self.free_list.pop()
            self.note_to_address[note_id] = address
            # CRITICAL: We do not clear the data residing at this address!
        else:
            # Normal Allocation: Provision a brand new block of memory
            address = self.next_address
            self.next_address += 0x1000
            self.note_to_address[note_id] = address
            self.blocks[address] = default_data

    def write(self, note_id, data):
        address = self.note_to_address.get(note_id)
        if address:
            self.blocks[address] = data

    def read(self, note_id):
        address = self.note_to_address.get(note_id)
        return self.blocks.get(address, "")

    def free(self, note_id):
        address = self.note_to_address.get(note_id)
        if address and address not in self.free_list:
            self.free_list.append(address) # Pushed to the top of the stack


class CTFApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NoteBad")
        self.root.geometry("450x350")
        
        self.heap = SimulatedHeap()
        self.active_notes = [] 
        
        self.setup_vulnerable_environment()
        self.show_dashboard()

    def setup_vulnerable_environment(self):
        self.heap.allocate(2, "Star Wars is a great series.")
        self.heap.allocate(3, "The Matrix is also very good.")

        self.heap.allocate(1, "Boss is gonna fire me today\nFlag: u53_4ft3r_fr33_m3m0ry_l34k")
        self.heap.free(1)
        
        self.active_notes = [2, 3]
        self.next_id = 4 

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_dashboard(self):
        self.clear_frame()
        tk.Label(self.root, text="📝 NoteBad", font=("Default", 16, "bold", "italic"), fg="purple").pack(pady=15)
        tk.Label(self.root, text="Your personal note taking app", font=("Default", 12), fg="grey").pack(pady=15)
        
        self.listbox = tk.Listbox(self.root, width=50, height=8)
        self.listbox.pack(pady=5)
        
        for nid in self.active_notes:
            self.listbox.insert(tk.END, f"Note ID: {nid}")
            
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=15)

        tk.Button(btn_frame, text="Delete Note", width=11, command=self.delete_note).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="View Note", width=11, command=self.view_note).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Create Note", width=11, command=self.create_note).pack(side=tk.LEFT, padx=5)
        

    def view_note(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Action Required", "Select a note to read.")
            return
            
        index = selection[0]
        nid = self.active_notes[index]
        content = self.heap.read(nid)
        
        self.clear_frame()
        tk.Label(self.root, text=f"Viewing Note ID: {nid}", font=("Arial", 14, "bold")).pack(pady=15)
        
        content_display = tk.Text(self.root, width=40, height=8, bg="#f5f5f5", relief="sunken", wrap="word", font=("Arial", 10))
        content_display.insert(tk.END, content)
        
        content_display.config(state=tk.DISABLED) 
        content_display.pack(pady=10)
        
        tk.Button(self.root, text="Back to Dashboard", width=20, command=self.show_dashboard).pack(pady=10)

    def delete_note(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Action Required", "Select a note to delete.")
            return
            
        index = selection[0]
        nid = self.active_notes[index]
        
        self.heap.free(nid)
        self.active_notes.remove(nid)
        
        messagebox.showinfo("Success", f"Note ID {nid} deleted successfully.")
        self.show_dashboard()

    def create_note(self):
        self.clear_frame()
        
        current_creation_id = self.next_id
        self.next_id += 1
        
        self.heap.allocate(current_creation_id)
        self.active_notes.append(current_creation_id)
        
        tk.Label(self.root, text=f"Drafting Note ID: {current_creation_id}", font=("Arial", 14, "bold")).pack(pady=15)
        
        text_area = tk.Text(self.root, width=40, height=8)
        text_area.pack(pady=10)
        
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        def save_note():
            content = text_area.get("1.0", tk.END).strip()
            self.heap.write(current_creation_id, content)
            self.show_dashboard()
            
        def back_without_saving():
            self.show_dashboard()
            
        # CHANGED: Button order set to Back -> Save Note
        tk.Button(btn_frame, text="Back", width=12, command=back_without_saving).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Save Note", width=12, command=save_note).pack(side=tk.LEFT, padx=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = CTFApp(root)
    root.mainloop()