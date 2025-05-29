import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import threading
import time
import sys

class HashCrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hash Cracker")
        self.root.geometry("820x650")
        self.dark_mode = True
        self.setup_colors()

        # Variables
        self.hash_file = None
        self.wordlist_file = None
        self.hash_method = tk.StringVar(value="MD5")
        self.manual_hash = tk.StringVar()
        self.stop_flag = threading.Event()

        # UI Setup
        self.build_ui()

        # Data containers
        self.hashed_wordlist = {}

    def setup_colors(self):
        if self.dark_mode:
            self.bg = "#1e1e1e"
            self.fg = "#00ffcc"   # header text color
            self.txt_bg = "#282828"
            self.btn_bg = "#333333"
            self.radio_select_color = "#ff4444"  # bright red for dark mode
            self.entry_bg = "#404040"
            self.crack_btn_bg = "#00ffcc"  # same as header text color
            self.crack_btn_fg = "black"
        else:
            self.bg = "#f0f0f0"
            self.fg = "#000080"
            self.txt_bg = "#ffffff"
            self.btn_bg = "#dddddd"
            self.radio_select_color = "#0000ff"  # blue for light mode
            self.entry_bg = "#ffffff"
            self.crack_btn_bg = "#00ffcc"  # keep same in light mode for consistency
            self.crack_btn_fg = "black"
        self.root.configure(bg=self.bg)

    def build_ui(self):
        # Header
        self.header_label = tk.Label(self.root, text="Hash Cracker", font=("Arial", 26, "bold"), bg=self.bg, fg=self.fg)
        self.header_label.pack(pady=10)

        # Hash method frame with radio buttons
        method_frame = tk.Frame(self.root, bg=self.bg)
        method_frame.pack(pady=5)
        tk.Label(method_frame, text="Select Hash Method:", font=("Arial", 12, "bold"), bg=self.bg, fg=self.fg).pack(anchor="w")

        hash_methods = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
        for method in hash_methods:
            rb = tk.Radiobutton(
                method_frame, text=method, variable=self.hash_method, value=method,
                font=("Arial", 10), bg=self.bg, fg=self.fg,
                selectcolor=self.radio_select_color,
                activebackground=self.bg, activeforeground=self.fg,
                indicatoron=1
            )
            rb.pack(side=tk.LEFT, padx=12, pady=5)

        # Manual hash input
        manual_frame = tk.Frame(self.root, bg=self.bg)
        manual_frame.pack(pady=10, fill="x", padx=20)
        tk.Label(manual_frame, text="Or enter a single hash manually:", bg=self.bg, fg=self.fg, font=("Arial", 11, "bold")).pack(anchor="w")
        self.manual_entry = tk.Entry(manual_frame, textvariable=self.manual_hash, font=("Courier", 12), bg=self.entry_bg, fg=self.fg, insertbackground=self.fg)
        self.manual_entry.pack(fill="x", pady=5)

        # File selection buttons
        file_frame = tk.Frame(self.root, bg=self.bg)
        file_frame.pack(pady=10)
        self.hash_button = tk.Button(file_frame, text="Select Hash File", width=22, command=self.load_hash_file,
                                     bg=self.btn_bg, fg=self.fg, font=("Arial", 12, "bold"))
        self.hash_button.pack(side=tk.LEFT, padx=10)

        self.wordlist_button = tk.Button(file_frame, text="Select Wordlist File", width=22, command=self.load_wordlist_file,
                                        bg=self.btn_bg, fg=self.fg, font=("Arial", 12, "bold"))
        self.wordlist_button.pack(side=tk.LEFT, padx=10)

        # Status & progress
        self.status_label = tk.Label(self.root, text="", font=("Arial", 10), fg=self.fg, bg=self.bg)
        self.status_label.pack(pady=5)

        self.progress = ttk.Progressbar(self.root, length=700, mode='determinate')
        self.progress.pack(pady=5)

        # Buttons for cracking and stopping
        btn_frame = tk.Frame(self.root, bg=self.bg)
        btn_frame.pack(pady=10)
        self.crack_button = tk.Button(btn_frame, text="Crack Hash", width=20, command=self.start_crack_thread,
                                      bg=self.crack_btn_bg, fg=self.crack_btn_fg, font=("Arial", 14, "bold"), state=tk.DISABLED)
        self.crack_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(btn_frame, text="Stop", width=20, command=self.stop_crack,
                                     bg="#999999", fg="white", font=("Arial", 14, "bold"), state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10)

        # Result text area
        self.result_text = tk.Text(self.root, height=18, width=90, state=tk.DISABLED, font=("Courier", 11),
                                   bg=self.txt_bg, fg=self.fg)
        self.result_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Copy & save buttons
        save_copy_frame = tk.Frame(self.root, bg=self.bg)
        save_copy_frame.pack(pady=10)
        self.copy_button = tk.Button(save_copy_frame, text="Copy Results", width=20, command=self.copy_results,
                                     bg="#69995D", fg="white", font=("Arial", 12, "bold"), state=tk.DISABLED)
        self.copy_button.pack(side=tk.LEFT, padx=10)

        self.save_button = tk.Button(save_copy_frame, text="Save Results", width=20, command=self.save_results,
                                     bg="#69995D", fg="white", font=("Arial", 12, "bold"), state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=10)

        # Light/Dark mode toggle
        theme_frame = tk.Frame(self.root, bg=self.bg)
        theme_frame.pack(pady=10)
        self.theme_button = tk.Button(theme_frame, text="Toggle Light/Dark Mode", command=self.toggle_theme,
                                      bg=self.btn_bg, fg=self.fg, font=("Arial", 12, "bold"))
        self.theme_button.pack()

        # Event bindings to enable crack button
        self.manual_hash.trace_add("write", lambda *_: self.update_crack_button_state())

    def load_hash_file(self):
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file:
            self.hash_file = file
            self.status_label.config(text=f"Hash file selected: {file}", fg=self.fg)
            self.update_crack_button_state()

    def load_wordlist_file(self):
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file:
            self.wordlist_file = file
            self.status_label.config(text=f"Wordlist file selected: {file}", fg=self.fg)
            self.update_crack_button_state()

    def update_crack_button_state(self):
        manual_hash_ok = bool(self.manual_hash.get().strip())
        files_ok = self.hash_file is not None and self.wordlist_file is not None
        if manual_hash_ok or files_ok:
            self.crack_button.config(state=tk.NORMAL)
        else:
            self.crack_button.config(state=tk.DISABLED)

    def start_crack_thread(self):
        self.crack_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Starting cracking...", fg=self.fg)
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        self.progress['value'] = 0
        self.stop_flag.clear()

        threading.Thread(target=self.crack_hash).start()

    def stop_crack(self):
        self.stop_flag.set()
        self.status_label.config(text="Stopping... please wait.", fg="orange")
        self.stop_button.config(state=tk.DISABLED)

    def crack_hash(self):
        try:
            start_time = time.time()
            if self.manual_hash.get().strip():
                target_hashes = [self.manual_hash.get().strip().lower()]
            else:
                with open(self.hash_file, "r", encoding="utf-8", errors="ignore") as hf:
                    target_hashes = [line.strip().lower() for line in hf if line.strip()]

            expected_len = self.get_hash_length()
            for h in target_hashes:
                if len(h) != expected_len:
                    self.show_error(f"Hash length mismatch for method {self.hash_method.get()}: {h}")
                    self.reset_ui_after_crack()
                    return

            self.status_label.config(text="Hashing wordlist, please wait...", fg=self.fg)
            self.hashed_wordlist.clear()

            with open(self.wordlist_file, "r", encoding="utf-8", errors="ignore") as wf:
                words = [line.strip() for line in wf if line.strip()]

            total_words = len(words)
            if total_words == 0:
                self.show_error("Wordlist file is empty.")
                self.reset_ui_after_crack()
                return

            for idx, word in enumerate(words):
                if self.stop_flag.is_set():
                    self.status_label.config(text="Cracking stopped by user.", fg="orange")
                    self.reset_ui_after_crack()
                    return
                hsh = self.compute_hash(word)
                self.hashed_wordlist[hsh] = word
                if idx % 1000 == 0 or idx == total_words - 1:
                    self.progress['value'] = (idx + 1) / total_words * 50
                    self.status_label.config(text=f"Hashing wordlist: {idx + 1}/{total_words}", fg=self.fg)
                    self.root.update_idletasks()

            self.status_label.config(text="Cracking hashes...", fg=self.fg)
            results = []
            total_targets = len(target_hashes)
            for idx, t_hash in enumerate(target_hashes):
                if self.stop_flag.is_set():
                    self.status_label.config(text="Cracking stopped by user.", fg="orange")
                    self.reset_ui_after_crack()
                    return
                word_found = self.hashed_wordlist.get(t_hash)
                if word_found:
                    results.append(f"{t_hash[:6]}...{t_hash[-6:]} -> {word_found}")
                else:
                    results.append(f"{t_hash[:6]}...{t_hash[-6:]} -> Not found")

                self.progress['value'] = 50 + ((idx + 1) / total_targets) * 50
                self.status_label.config(text=f"Cracking hashes: {idx + 1}/{total_targets}", fg=self.fg)
                self.root.update_idletasks()

            elapsed = time.time() - start_time
            self.display_result("\n".join(results))
            self.status_label.config(text=f"Cracking completed in {elapsed:.2f} seconds.", fg="lightgreen")
            self.save_button.config(state=tk.NORMAL)
            self.copy_button.config(state=tk.NORMAL)

        except Exception as e:
            self.show_error(f"Error during cracking: {e}")
        finally:
            self.reset_ui_after_crack()

    def compute_hash(self, word):
        try:
            hasher = hashlib.new(self.hash_method.get().replace("-", "").lower())
        except Exception:
            hasher = hashlib.md5()
        hasher.update(word.encode("utf-8"))
        return hasher.hexdigest().lower()

    def get_hash_length(self):
        method = self.hash_method.get().upper()
        return {
            "MD5": 32,
            "SHA-1": 40,
            "SHA-256": 64,
            "SHA-512": 128
        }.get(method, 32)

    def display_result(self, message):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, message)
        self.result_text.config(state=tk.DISABLED)

    def copy_results(self):
        self.root.clipboard_clear()
        text = self.result_text.get(1.0, tk.END).strip()
        if text:
            self.root.clipboard_append(text)
            messagebox.showinfo("Copied", "Results copied to clipboard!")

    def save_results(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file:
            with open(file, "w", encoding="utf-8") as f:
                f.write(self.result_text.get(1.0, tk.END))
            messagebox.showinfo("Saved", f"Results saved to {file}")

    def show_error(self, msg):
        messagebox.showerror("Error", msg)

    def reset_ui_after_crack(self):
        self.crack_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress['value'] = 0

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.setup_colors()

        self.root.configure(bg=self.bg)
        self.header_label.config(bg=self.bg, fg=self.fg)
        self.status_label.config(bg=self.bg, fg=self.fg)
        self.result_text.config(bg=self.txt_bg, fg=self.fg, insertbackground=self.fg)
        self.manual_entry.config(bg=self.entry_bg, fg=self.fg, insertbackground=self.fg)

        self.hash_button.config(bg=self.btn_bg, fg=self.fg)
        self.wordlist_button.config(bg=self.btn_bg, fg=self.fg)
        self.crack_button.config(bg=self.crack_btn_bg, fg=self.crack_btn_fg)
        self.stop_button.config(bg="#999999", fg="white")
        self.copy_button.config(bg="#69995D", fg="white")
        self.save_button.config(bg="#69995D", fg="white")
        self.theme_button.config(bg=self.btn_bg, fg=self.fg)

        for child in self.root.winfo_children():
            if isinstance(child, tk.Frame):
                for widget in child.winfo_children():
                    if isinstance(widget, tk.Radiobutton):
                        widget.config(bg=self.bg, fg=self.fg, selectcolor=self.radio_select_color,
                                      activebackground=self.bg, activeforeground=self.fg)
                child.config(bg=self.bg)

        self.update_crack_button_state()

if __name__ == "__main__":
    root = tk.Tk()
    app = HashCrackerApp(root)
    root.mainloop()
