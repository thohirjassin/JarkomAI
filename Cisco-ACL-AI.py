import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

# --- KONSTANTA & FUNGSI UTAMA ---

COMMON_PORTS = {
    "21 (FTP)": "21",
    "22 (SSH)": "22",
    "23 (Telnet)": "23",
    "25 (SMTP)": "25",
    "53 (DNS)": "53",
    "80 (HTTP)": "80",
    "110 (POP3)": "110",
    "143 (IMAP)": "143",
    "443 (HTTPS)": "443",
    "3389 (RDP)": "3389",
}

def subnet_to_wildcard(subnet_mask):
    """Mengonversi subnet mask menjadi wildcard mask."""
    if not subnet_mask: return ""
    try:
        octets = subnet_mask.split('.')
        if len(octets) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            return "Error: Subnet Mask tidak valid"
        wildcard_octets = [str(255 - int(o)) for o in octets]
        return '.'.join(wildcard_octets)
    except Exception:
        return "Error: Format Subnet Mask salah"

def update_preview(event=None):
    """Memperbarui label pratinjau secara real-time berdasarkan input."""
    # Action & Protocol
    action = action_var.get()
    protocol = protocol_var.get()

    # Proses Source
    source_ip = source_ip_entry.get().strip().lower() or "any"
    if source_ip == "any":
        source_part = "any"
    else:
        source_wildcard = subnet_to_wildcard(source_mask_entry.get().strip())
        source_part = f"host {source_ip}" if not source_mask_entry.get().strip() or source_mask_entry.get() == "255.255.255.255" else f"{source_ip} {source_wildcard}"

    # Proses Destination
    dest_ip = dest_ip_entry.get().strip().lower() or "any"
    if dest_ip == "any":
        dest_part = "any"
    else:
        dest_wildcard = subnet_to_wildcard(dest_mask_entry.get().strip())
        dest_part = f"host {dest_ip}" if not dest_mask_entry.get().strip() or dest_mask_entry.get() == "255.255.255.255" else f"{dest_ip} {dest_wildcard}"

    # Proses Port (jika TCP/UDP)
    port_part = ""
    if protocol in ["tcp", "udp"]:
        operator = port_operator_var.get()
        port_input = port_var.get().strip()

        # Ekstrak nomor port dari format "80 (HTTP)"
        port_num = COMMON_PORTS.get(port_input, port_input)

        if operator and port_num:
            port_part = f" {operator} {port_num}"

    # Gabungkan semua bagian menjadi perintah dan tampilkan di preview
    rule_preview = f"{action} {protocol} {source_part} {dest_part}{port_part}"
    preview_label.config(text=rule_preview)
    return rule_preview

def add_rule_to_list():
    """Menambahkan rule dari pratinjau ke text area output."""
    acl_name = acl_name_entry.get().strip()
    if not acl_name:
        messagebox.showwarning("Input Diperlukan", "Silakan masukkan Nama atau Nomor ACL terlebih dahulu.")
        return

    # Jika ini adalah rule pertama, tambahkan header ACL
    current_output = output_text.get("1.0", "end-1c")
    if not current_output.strip():
        header = f"ip access-list extended {acl_name}\n"
        output_text.insert("1.0", header)

    # Cek apakah nama ACL di header sama dengan yang di input
    elif not current_output.startswith(f"ip access-list extended {acl_name}"):
         if messagebox.askyesno("Konfirmasi", "Nama ACL berbeda dari yang sudah ada. Mulai ACL baru?"):
             output_text.delete("1.0", tk.END)
             header = f"ip access-list extended {acl_name}\n"
             output_text.insert("1.0", header)
         else:
             return

    rule_to_add = preview_label.cget("text")
    if "Error:" in rule_to_add:
        messagebox.showerror("Error", "Tidak dapat menambahkan aturan. Perbaiki error pada subnet mask.")
        return

    output_text.insert(tk.END, f" {rule_to_add}\n") # Tambahkan spasi untuk indentasi

def toggle_port_fields(event=None):
    """Aktifkan/Nonaktifkan field port berdasarkan protokol yang dipilih."""
    protocol = protocol_var.get().lower()
    if protocol in ["tcp", "udp"]:
        port_operator_combo.config(state="readonly")
        port_combo.config(state="normal")
    else:
        port_operator_combo.config(state="disabled")
        port_combo.config(state="disabled")
        port_operator_var.set("")
        port_var.set("")
    update_preview() # Update preview saat protokol diubah

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(output_text.get("1.0", "end-1c"))
    messagebox.showinfo("Berhasil", "Konfigurasi ACL telah disalin ke clipboard.")

def save_to_file():
    config = output_text.get("1.0", "end-1c")
    if not config:
        messagebox.showwarning("Kosong", "Tidak ada konfigurasi untuk disimpan.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, 'w') as f: f.write(config)
        messagebox.showinfo("Berhasil", f"Konfigurasi telah disimpan di:\n{file_path}")

def clear_all():
    if messagebox.askokcancel("Konfirmasi", "Anda yakin ingin membersihkan semua input dan output?"):
        # Hapus binding untuk mencegah update preview saat membersihkan
        for widget in all_input_widgets:
            widget.unbind_all("<KeyRelease>")
            widget.unbind_all("<<ComboboxSelected>>")

        acl_name_entry.delete(0, tk.END)
        action_var.set("permit")
        protocol_var.set("ip")
        source_ip_entry.delete(0, tk.END)
        source_mask_entry.delete(0, tk.END)
        dest_ip_entry.delete(0, tk.END)
        dest_mask_entry.delete(0, tk.END)
        port_operator_var.set("")
        port_var.set("")
        output_text.delete("1.0", tk.END)

        # Kembalikan binding setelah selesai
        bind_all_widgets()
        toggle_port_fields()
        update_preview()

# --- PENGATURAN GUI ---
root = tk.Tk()
root.title("Cisco ACL Generator v2.0")
root.geometry("950x700")
root.minsize(850, 650)

# Style
style = ttk.Style()
style.configure("TLabel", font=("Segoe UI", 10))
style.configure("TButton", font=("Segoe UI", 10, "bold"))
style.configure("TCombobox", font=("Segoe UI", 10))
style.configure("TEntry", font=("Segoe UI", 10))
style.configure("Preview.TLabel", font=("Consolas", 11, "bold"), background="#e0e0e0", padding=5)
style.configure("TLabelframe.Label", font=("Segoe UI", 11, "bold"))

main_frame = ttk.Frame(root, padding="10")
main_frame.pack(fill="both", expand=True)

# --- Kolom Kiri: Input Form ---
input_frame = ttk.Labelframe(main_frame, text="1. Buat Aturan ACL")
input_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

# ACL Name, Action, Protocol... (sama seperti sebelumnya)
# ... [Bagian ini tidak berubah signifikan, hanya penambahan binding]
acl_name_frame = ttk.Frame(input_frame); acl_name_frame.pack(fill="x", pady=5)
ttk.Label(acl_name_frame, text="Nama ACL:", width=15).pack(side="left")
acl_name_entry = ttk.Entry(acl_name_frame)
acl_name_entry.pack(side="left", fill="x", expand=True)

action_frame = ttk.Frame(input_frame); action_frame.pack(fill="x", pady=5)
ttk.Label(action_frame, text="Aksi:", width=15).pack(side="left")
action_var = tk.StringVar(value="permit")
action_combo = ttk.Combobox(action_frame, textvariable=action_var, values=["permit", "deny"], state="readonly")
action_combo.pack(side="left", fill="x", expand=True)

protocol_frame = ttk.Frame(input_frame); protocol_frame.pack(fill="x", pady=5)
ttk.Label(protocol_frame, text="Protokol:", width=15).pack(side="left")
protocol_var = tk.StringVar(value="ip")
protocol_combo = ttk.Combobox(protocol_frame, textvariable=protocol_var, values=["ip", "tcp", "udp", "icmp"], state="readonly")
protocol_combo.pack(side="left", fill="x", expand=True)

source_frame = ttk.LabelFrame(input_frame, text="Sumber (Source)"); source_frame.pack(fill="x", pady=10, ipady=5)
ttk.Label(source_frame, text="IP Address:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
source_ip_entry = ttk.Entry(source_frame)
source_ip_entry.grid(row=0, column=1, sticky="ew", padx=5)
ttk.Label(source_frame, text="Subnet Mask:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
source_mask_entry = ttk.Entry(source_frame)
source_mask_entry.grid(row=1, column=1, sticky="ew", padx=5)
source_frame.columnconfigure(1, weight=1)

dest_frame = ttk.LabelFrame(input_frame, text="Tujuan (Destination)"); dest_frame.pack(fill="x", pady=10, ipady=5)
ttk.Label(dest_frame, text="IP Address:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
dest_ip_entry = ttk.Entry(dest_frame)
dest_ip_entry.grid(row=0, column=1, sticky="ew", padx=5)
ttk.Label(dest_frame, text="Subnet Mask:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
dest_mask_entry = ttk.Entry(dest_frame)
dest_mask_entry.grid(row=1, column=1, sticky="ew", padx=5)
dest_frame.columnconfigure(1, weight=1)

# Port Frame (Diperbarui dengan Combobox)
port_frame = ttk.LabelFrame(input_frame, text="Port (untuk TCP/UDP)"); port_frame.pack(fill="x", pady=10, ipady=5)
ttk.Label(port_frame, text="Operator:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
port_operator_var = tk.StringVar()
port_operator_combo = ttk.Combobox(port_frame, textvariable=port_operator_var, values=["eq", "neq", "gt", "lt", "range"], state="disabled", width=10)
port_operator_combo.grid(row=0, column=1, sticky="ew", padx=5)

ttk.Label(port_frame, text="Nomor Port:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
port_var = tk.StringVar()
port_combo = ttk.Combobox(port_frame, textvariable=port_var, values=list(COMMON_PORTS.keys()), state="disabled")
port_combo.grid(row=1, column=1, sticky="ew", padx=5)
port_frame.columnconfigure(1, weight=1)

# Live Preview Frame (BARU)
preview_frame = ttk.Labelframe(input_frame, text="Live Preview")
preview_frame.pack(fill="x", pady=(15, 5), ipady=5)
preview_label = ttk.Label(preview_frame, text="", style="Preview.TLabel", anchor="w")
preview_label.pack(fill="x", padx=5, pady=5)

# Tombol Tambah Aturan
add_button = ttk.Button(input_frame, text="Tambahkan Aturan ke Daftar", command=add_rule_to_list)
add_button.pack(fill="x", ipady=5, pady=(5, 5))

# --- Kolom Kanan: Output & Actions ---
output_frame = ttk.Labelframe(main_frame, text="2. Hasil Konfigurasi ACL")
output_frame.pack(side="left", fill="both", expand=True)

output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, font=("Consolas", 11), height=10)
output_text.pack(fill="both", expand=True)

output_action_frame = ttk.Frame(output_frame, padding=(0, 10, 0, 0))
output_action_frame.pack(fill="x")
copy_button = ttk.Button(output_action_frame, text="Salin ke Clipboard", command=copy_to_clipboard)
copy_button.pack(side="left", expand=True, fill="x", padx=(0, 5))
save_button = ttk.Button(output_action_frame, text="Simpan ke File", command=save_to_file)
save_button.pack(side="left", expand=True, fill="x")

clear_button = ttk.Button(main_frame, text="BERSIHKAN SEMUA", command=clear_all)
clear_button.pack(side="bottom", fill="x", pady=(10,0), ipady=5)

# --- Binding Events untuk Live Update ---
all_input_widgets = [
    acl_name_entry, source_ip_entry, source_mask_entry, dest_ip_entry, dest_mask_entry,
    action_combo, protocol_combo, port_operator_combo, port_combo
]

def bind_all_widgets():
    # Bind event untuk entry (saat keyboard dilepas)
    for widget in [acl_name_entry, source_ip_entry, source_mask_entry, dest_ip_entry, dest_mask_entry, port_combo]:
        widget.bind("<KeyRelease>", update_preview)
    # Bind event untuk combobox (saat item dipilih)
    for widget in [action_combo, protocol_combo, port_operator_combo, port_combo]:
        widget.bind("<<ComboboxSelected>>", update_preview)
    # Protocol combo juga butuh toggle
    protocol_combo.bind("<<ComboboxSelected>>", toggle_port_fields, add="+")

bind_all_widgets()
toggle_port_fields()
update_preview()

root.mainloop()
