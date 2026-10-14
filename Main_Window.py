# Names:
# Brenden Toussant

import socket
import threading
import tkinter as tk
from tkinter import ttk

import nmap


def asset_discovery():
    """Returns a list of (host, protocol, port, state) tuples."""
    hostname = socket.gethostname()
    targetIPAddr = socket.gethostbyname(hostname)
    nm = nmap.PortScanner()
    nm.scan(targetIPAddr, '22-446')

    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                results.append((host, proto, port, nm[host][proto][port]['state']))
    return results


# ---------- GUI ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Attack Surface Management Tool") #Sets title of the window
        self.geometry("600x400") #Sets the dimensions of the window

        self.button = ttk.Button(self, text="Run Asset Discovery", command=self.run_scan) #Creates button
        self.button.pack(pady=10)

        cols = ("Host", "Protocol", "Port", "State")
        self.table = ttk.Treeview(self, columns=cols, show="headings")
        for c in cols:
            self.table.heading(c, text=c)
            self.table.column(c, width=130)
        self.table.pack(fill="both", expand=True, padx=10)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status).pack(pady=5)

    def run_scan(self):
        self.button.config(state="disabled")
        self.status.set("Scanning...")
        # Thread keeps the window from freezing during the scan
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        try:
            results = asset_discovery()
            self.after(0, self._show_results, results)  # hand results back to the GUI thread
        except Exception as e:
            self.after(0, self.status.set, f"Error: {e}")
            self.after(0, lambda: self.button.config(state="normal"))

    def _show_results(self, results):
        self.table.delete(*self.table.get_children())
        for row in results:
            self.table.insert("", "end", values=row)
        self.status.set(f"Done. {len(results)} port(s) found.")
        self.button.config(state="normal")


if __name__ == "__main__":
    App().mainloop()
