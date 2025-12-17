import os
import json
import hashlib
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

HEADER = "ENCRYPTED-NOTEPAD:v1"
MASTER_STORE = os.path.join(os.path.expanduser("~"), ".enc_notepad_master.json")


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _derive_keystream(password: str, salt: bytes, length: int) -> bytes:
    pwb = password.encode("utf-8")
    block = salt + pwb
    out = b""
    counter = 0
    while len(out) < length:
        out += _sha256(block + counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    ks = _derive_keystream(password, salt, len(plaintext))
    cipher = bytes(a ^ b for a, b in zip(plaintext, ks))
    payload = HEADER + "\n" + salt.hex() + "\n" + cipher.hex()
    return payload.encode("utf-8")


def decrypt_bytes(data: bytes, password: str) -> bytes:
    try:
        s = data.decode("utf-8")
        h, salt_hex, cipher_hex = s.split("\n", 2)
        if h != HEADER:
            raise ValueError("Not an encrypted notepad file")
        salt = bytes.fromhex(salt_hex)
        cipher = bytes.fromhex(cipher_hex)
        ks = _derive_keystream(password, salt, len(cipher))
        plain = bytes(a ^ b for a, b in zip(cipher, ks))
        return plain
    except Exception:
        raise ValueError("Decryption failed")


def _master_exists() -> bool:
    return os.path.isfile(MASTER_STORE)


def _set_master_password_interactive(root):
    if _master_exists():
        old = simpledialog.askstring("Change master", "Current master password:", show="*")
        if old is None:
            return
        if not verify_master_password(old):
            messagebox.showerror("Error", "Current master password incorrect.")
            return
    while True:
        pw1 = simpledialog.askstring("Master password", "Enter new master password:", show="*")
        if pw1 is None:
            return
        pw2 = simpledialog.askstring("Master password", "Confirm new master password:", show="*")
        if pw2 is None:
            return
        if pw1 != pw2:
            messagebox.showerror("Mismatch", "Passwords do not match, try again.")
            continue
        salt = os.urandom(16)
        h = hashlib.sha256(salt + pw1.encode("utf-8")).hexdigest()
        with open(MASTER_STORE, "w") as f:
            json.dump({"salt": salt.hex(), "hash": h}, f)
        messagebox.showinfo("Saved", "Master password set.")
        return


def verify_master_password(password: str) -> bool:
    if not _master_exists():
        return False
    with open(MASTER_STORE, "r") as f:
        obj = json.load(f)
    salt = bytes.fromhex(obj["salt"])
    expected = obj["hash"]
    h = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
    return h == expected


class EncryptedNotepad:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Notepad - encrypted note")
        self.filepath = None
        self.last_password_used = None
        self.dark_mode = True

        self.text = tk.Text(root, wrap="word")
        self.text.pack(fill="both", expand=True)

        self.menubar = None
        self.file_menu = None
        self.settings_menu = None

        self._build_menu()
        self.apply_theme()
        self._bind_shortcuts()

        self.text.edit_modified(False)

    def _build_menu(self):
        self.menubar = tk.Menu(self.root)

        self.file_menu = tk.Menu(self.menubar, tearoff=0)
        self.file_menu.add_command(label="New", command=self.new_file, accelerator="Ctrl+N")
        self.file_menu.add_command(label="Open...", command=self.open_file, accelerator="Ctrl+O")
        self.file_menu.add_command(label="Save", command=self.save_file, accelerator="Ctrl+S")
        self.file_menu.add_command(label="Save As...", command=self.save_as_file, accelerator="Ctrl+Shift+S")
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")
        self.menubar.add_cascade(label="File", menu=self.file_menu)

        self.settings_menu = tk.Menu(self.menubar, tearoff=0)
        self.settings_menu.add_command(label="Set/Change Master Password", command=lambda: _set_master_password_interactive(self.root), accelerator="Ctrl+M")
        self.settings_menu.add_command(label="Toggle Dark Mode", command=self.toggle_dark_mode, accelerator="Ctrl+D")
        self.menubar.add_cascade(label="Settings", menu=self.settings_menu)

        self.root.config(menu=self.menubar)

    def apply_theme(self):
        if self.dark_mode:
            bg = "#1e1e1e"
            fg = "#dcdcdc"
            insert = "#ffffff"
            menu_bg = "#2b2b2b"
            menu_fg = "#eaeaea"
            active_bg = "#3a3a3a"
            active_fg = "#ffffff"
        else:
            bg = "SystemButtonFace"
            fg = "black"
            insert = "black"
            menu_bg = None
            menu_fg = None
            active_bg = None
            active_fg = None

        try:
            self.root.configure(bg=bg)
        except Exception:
            pass
        self.text.configure(bg=bg, fg=fg, insertbackground=insert, selectbackground=active_bg or "#cde", relief="flat")

        try:
            if menu_bg is not None:
                self.menubar.configure(bg=menu_bg, fg=menu_fg)
                self.file_menu.configure(bg=menu_bg, fg=menu_fg, activebackground=active_bg, activeforeground=active_fg)
                self.settings_menu.configure(bg=menu_bg, fg=menu_fg, activebackground=active_bg, activeforeground=active_fg)
            else:
                self.root.config(menu=None)
                self._build_menu()
        except Exception:
            pass

    def toggle_dark_mode(self, event=None):
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    def new_file(self, event=None):
        if self._maybe_save():
            self.text.delete("1.0", "end")
            self.filepath = None
            self.last_password_used = None
            self.root.title("Encrypted Notepad - encrypted note")
            self.text.edit_modified(False)

    def open_file(self, event=None):
        if not self._maybe_save():
            return
        path = filedialog.askopenfilename(title="Open encrypted note", filetypes=[("All files", "*.*")])
        if not path:
            return
        pwd = simpledialog.askstring("Password", "Enter password to decrypt this note:", show="*")
        if pwd is None:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            plain = decrypt_bytes(data, pwd)
            self.text.delete("1.0", "end")
            self.text.insert("1.0", plain.decode("utf-8"))
            self.filepath = path
            self.last_password_used = pwd
            self.root.title(f"Encrypted Notepad - {os.path.basename(path)}")
            self.text.edit_modified(False)
        except Exception:
            messagebox.showerror("Error", "Failed to decrypt file (wrong password or invalid file).")

    def save_file(self, event=None):
        if not self.filepath:
            return self.save_as_file()
        use_master = messagebox.askyesno("Encrypt with master?", "Encrypt with master password? (No to set a custom password for this note)")
        if use_master:
            if not _master_exists():
                messagebox.showinfo("No master", "No master password set. Set one now.")
                _set_master_password_interactive(self.root)
                if not _master_exists():
                    return
            pwd = simpledialog.askstring("Master password", "Enter master password:", show="*")
            if pwd is None:
                return
            if not verify_master_password(pwd):
                messagebox.showerror("Error", "Master password incorrect.")
                return
        else:
            pwd = simpledialog.askstring("Note password", "Enter password to encrypt this note:", show="*")
            if pwd is None:
                return
        try:
            plaintext = self.text.get("1.0", "end-1c").encode("utf-8")
            enc = encrypt_bytes(plaintext, pwd)
            with open(self.filepath, "wb") as f:
                f.write(enc)
            self.last_password_used = pwd
            self.text.edit_modified(False)
            messagebox.showinfo("Saved", "File saved (encrypted).")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    def save_as_file(self, event=None):
        path = filedialog.asksaveasfilename(title="Save encrypted note as",
                                            defaultextension=".enc",
                                            initialfile="encrypted note",
                                            filetypes=[("Encrypted note", "*.enc"), ("All files", "*.*")])
        if not path:
            return
        self.filepath = path
        self.save_file()

    def _maybe_save(self) -> bool:
        if self.text.edit_modified():
            res = messagebox.askyesnocancel("Save", "You have unsaved changes. Save now?")
            if res is None:
                return False
            if res:
                self.save_file()
        return True

    def _bind_shortcuts(self):
        binds = [
            ("<Control-s>", self.save_file),
            ("<Control-S>", self.save_file),
            ("<Control-Shift-s>", self.save_as_file),
            ("<Control-Shift-S>", self.save_as_file),
            ("<Control-o>", self.open_file),
            ("<Control-O>", self.open_file),
            ("<Control-n>", self.new_file),
            ("<Control-N>", self.new_file),
            ("<Control-q>", lambda e=None: self.root.quit()),
            ("<Control-Q>", lambda e=None: self.root.quit()),
            ("<Control-m>", lambda e=None: _set_master_password_interactive(self.root)),
            ("<Control-M>", lambda e=None: _set_master_password_interactive(self.root)),
            ("<Control-d>", self.toggle_dark_mode),
            ("<Control-D>", self.toggle_dark_mode),
            ("<Command-s>", self.save_file),
            ("<Command-Shift-s>", self.save_as_file),
            ("<Command-o>", self.open_file),
            ("<Command-n>", self.new_file),
            ("<Command-q>", lambda e=None: self.root.quit()),
            ("<Command-m>", lambda e=None: _set_master_password_interactive(self.root)),
            ("<Command-d>", self.toggle_dark_mode),
        ]
        for seq, handler in binds:
            try:
                self.root.bind_all(seq, lambda e, h=handler: h(e))
            except Exception:
                pass


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptedNotepad(root)
    if not _master_exists():
        if messagebox.askyesno("Master password", "No master password set. Would you like to set one now?"):
            _set_master_password_interactive(root)
    root.mainloop()
