import os
import re
import sys
import threading
import subprocess
from dataclasses import dataclass
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import pandas as pd

from pysnmp.hlapi import (
    SnmpEngine,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
    UsmUserData,
    usmHMACSHAAuthProtocol,            # SHA-1
    usmHMAC192SHA256AuthProtocol,      # SHA-256 family (truncated) per RFC 7860
    usmAesCfb128Protocol,              # AES-128
    usmAesCfb256Protocol,              # AES-256
)

# -------------------------
# Tunables
# -------------------------
PING_TIMEOUT_MS = 1000
SNMP_TIMEOUT_SECONDS = 3
SNMP_RETRIES = 1
SNMP_PORT = 161
MAX_SNMP_USERS = 6

TEST_OIDS = [
    "1.3.6.1.2.1.1.1.0",  # sysDescr.0
    "1.3.6.1.2.1.1.3.0",  # sysUpTime.0
    "1.3.6.1.2.1.1.5.0",  # sysName.0
]

AUTH_PROTOCOLS = {
    "SHA": usmHMACSHAAuthProtocol,               # SHA-1
    "SHA-256": usmHMAC192SHA256AuthProtocol,     # SHA-256 family
}

PRIV_PROTOCOLS = {
    "AES-128": usmAesCfb128Protocol,
    "AES-256": usmAesCfb256Protocol,
}

APP_TITLE = "SNMP Verification Tool"
APP_SUBTITLE = "Tool For SNMPv3 Validation Against Devices by Ramon Veluz"

WINDOW_BG = "#F5F5F5"
PANEL_BG = "#FFFFFF"
PANEL_ALT_BG = "#FAFAFA"
TEXT_PRIMARY = "#222222"
TEXT_SECONDARY = "#666666"
ACCENT = "#E7131A"
ACCENT_DARK = "#B5121B"
DANGER = "#4D4D4D"
DANGER_DARK = "#333333"
BORDER = "#D6D6D6"


@dataclass(frozen=True)
class CredentialConfig:
    username: str
    auth_password: str
    priv_password: str
    auth_proto: str
    priv_proto: str


@dataclass(frozen=True)
class RunConfig:
    file_path: str
    credentials: tuple[CredentialConfig, ...]
    write_debug_log: bool

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and PyInstaller """
    search_bases = []

    if getattr(sys, 'frozen', False):
        search_bases.append(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
        search_bases.append(os.path.dirname(sys.executable))
    else:
        search_bases.append(os.path.dirname(os.path.abspath(__file__)))
        search_bases.append(os.path.abspath("."))

    for base_path in search_bases:
        candidate = os.path.join(base_path, relative_path)
        if os.path.exists(candidate):
            return candidate

    return os.path.join(search_bases[0], relative_path)


def is_probably_ip(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    ip_regex = r"^\d{1,3}(\.\d{1,3}){3}$"
    if not re.match(ip_regex, value):
        return False
    parts = value.split(".")
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def find_ip_address_column(df: pd.DataFrame) -> str:
    for c in df.columns:
        if str(c).strip().lower() == "ip address":
            return c
    raise ValueError("Missing required column 'IP Address'.")


def ping_ip(ip: str) -> bool:
    """
    Runs Windows ping silently (no popping cmd windows).
    """
    try:
        startupinfo = None
        creationflags = 0

        if sys.platform.startswith("win"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW

        completed = subprocess.run(
            ["ping", "-n", "3", "-w", str(PING_TIMEOUT_MS), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        return completed.returncode == 0
    except Exception:
        return False


def snmp_test_v3_credentials(
    username: str,
    auth_password: str,
    priv_password: str,
    ip: str,
    auth_proto_name: str = "SHA",
    priv_proto_name: str = "AES-128",
    stop_requested: threading.Event | None = None,
) -> tuple[bool, str]:
    """
    Returns: (success: bool, detail: str)
    """
    try:
        auth_proto = AUTH_PROTOCOLS.get(auth_proto_name, usmHMACSHAAuthProtocol)
        priv_proto = PRIV_PROTOCOLS.get(priv_proto_name, usmAesCfb128Protocol)

        user_data = UsmUserData(
            userName=username,
            authKey=auth_password,
            privKey=priv_password,
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )

        target = UdpTransportTarget(
            (ip, SNMP_PORT),
            timeout=SNMP_TIMEOUT_SECONDS,
            retries=SNMP_RETRIES,
        )

        last_err = None
        for oid in TEST_OIDS:
            if stop_requested is not None and stop_requested.is_set():
                return False, "Stopped by user"

            iterator = getCmd(
                SnmpEngine(),
                user_data,
                target,
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )

            error_indication, error_status, error_index, var_binds = next(iterator)

            if error_indication:
                last_err = str(error_indication)
                continue
            if error_status:
                last_err = error_status.prettyPrint()
                continue
            if var_binds and len(var_binds) > 0:
                return True, "OK"

        return False, last_err or "No response / blocked / auth mismatch"
    except Exception as e:
        return False, f"Exception: {e}"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("880x570")
        self.minsize(840, 570)
        self.configure(bg=WINDOW_BG)
        self.option_add("*Font", ("Segoe UI", 10))
        try:
            self.iconbitmap(resource_path("app.ico"))
        except tk.TclError:
            pass
        self.file_path_var = tk.StringVar(value="")

        self.user_count_var = tk.IntVar(value=1)
        self.credential_vars = [
            {
                "username": tk.StringVar(value=""),
                "auth": tk.StringVar(value=""),
                "priv": tk.StringVar(value=""),
                "auth_proto": tk.StringVar(value="SHA"),
                "priv_proto": tk.StringVar(value="AES-128"),
            }
            for _ in range(MAX_SNMP_USERS)
        ]
        self.credential_sections: list[tk.Frame] = []

        # Debug option
        self.write_debug_log_var = tk.BooleanVar(value=True)

        # Stop flag
        self.stop_requested = threading.Event()

        self.status_var = tk.StringVar(value="Select an Excel file to begin.")
        self.progress_var = tk.StringVar(value="")
        self.progress_percent_var = tk.DoubleVar(value=0)

        self._build_ui()

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Primary.TButton",
            background=ACCENT,
            foreground="white",
            font=("Segoe UI", 9, "bold"),
            padding=(12, 6),
            borderwidth=0,
        )
        style.map(
            "Primary.TButton",
            background=[("active", ACCENT_DARK), ("disabled", "#B8B8B8")],
            foreground=[("active", "white"), ("disabled", "#F2F2F2")],
        )

        style.configure(
            "Danger.TButton",
            background=DANGER,
            foreground="white",
            font=("Segoe UI", 9, "bold"),
            padding=(12, 6),
            borderwidth=0,
        )
        style.map(
            "Danger.TButton",
            background=[("active", DANGER_DARK)],
            foreground=[("active", "white")],
        )

        style.configure(
            "Secondary.TButton",
            background="#EFEFEF",
            foreground=TEXT_PRIMARY,
            font=("Segoe UI", 9),
            padding=(12, 5),
            borderwidth=0,
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#E1E1E1")],
            foreground=[("active", TEXT_PRIMARY)],
        )

        style.configure(
            "Corporate.Horizontal.TProgressbar",
            troughcolor="#E6EAF0",
            background=ACCENT,
            bordercolor="#E6EAF0",
            lightcolor=ACCENT,
            darkcolor=ACCENT,
        )

        section_font = ("Segoe UI", 10, "bold")
        label_font = ("Segoe UI", 9)
        header_font = ("Segoe UI Semibold", 16)

        outer = tk.Frame(self, bg=WINDOW_BG)
        outer.pack(fill="both", expand=True, padx=12, pady=12)
        outer.grid_columnconfigure(0, weight=1)

        header = tk.Frame(
            outer,
            bg=PANEL_BG,
            highlightbackground=BORDER,
            highlightcolor=BORDER,
            highlightthickness=1,
            bd=0,
        )
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.grid_columnconfigure(1, weight=1)

        tk.Frame(header, bg=ACCENT, width=5).grid(row=0, column=0, sticky="ns")

        header_text = tk.Frame(header, bg=PANEL_BG, padx=12, pady=8)
        header_text.grid(row=0, column=1, sticky="ew")
        header_text.grid_columnconfigure(0, weight=1)

        tk.Label(
            header_text,
            text=APP_TITLE,
            bg=PANEL_BG,
            fg=TEXT_PRIMARY,
            font=header_font,
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            header_text,
            text=APP_SUBTITLE,
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=("Segoe UI", 9),
        ).grid(row=1, column=0, sticky="w", pady=(1, 0))

        content = tk.Frame(outer, bg=WINDOW_BG)
        content.grid(row=1, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)

        def make_panel(row: int, pady: tuple[int, int] = (0, 8)) -> tk.Frame:
            panel = tk.Frame(
                content,
                bg=PANEL_BG,
                highlightbackground=BORDER,
                highlightcolor=BORDER,
                highlightthickness=1,
                bd=0,
                padx=12,
                pady=10,
            )
            panel.grid(row=row, column=0, sticky="ew", pady=pady)
            panel.grid_columnconfigure(0, weight=1)
            return panel

        input_panel = make_panel(0)
        input_panel.grid_columnconfigure(1, weight=1)
        tk.Label(
            input_panel,
            text="Input workbook",
            bg=PANEL_BG,
            fg=TEXT_PRIMARY,
            font=section_font,
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))
        tk.Label(
            input_panel,
            text="Workbook (.xlsx)",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=1, column=0, sticky="w", padx=(0, 10))
        ttk.Entry(input_panel, textvariable=self.file_path_var).grid(
            row=1, column=1, sticky="ew", ipady=2
        )
        ttk.Button(
            input_panel,
            text="Browse",
            command=self.browse_file,
            style="Secondary.TButton",
        ).grid(row=1, column=2, sticky="e", padx=(10, 0))
        tk.Label(
            input_panel,
            text="Required column: IP Address",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=("Segoe UI", 8),
        ).grid(row=2, column=1, sticky="w", pady=(3, 0))

        credentials_panel = make_panel(1)
        credentials_panel.grid_columnconfigure(0, weight=1)
        tk.Label(
            credentials_panel,
            text="SNMPv3 credentials",
            bg=PANEL_BG,
            fg=TEXT_PRIMARY,
            font=section_font,
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))

        user_count_frame = tk.Frame(credentials_panel, bg=PANEL_BG)
        user_count_frame.grid(row=0, column=1, sticky="e", pady=(0, 8))
        tk.Label(
            user_count_frame,
            text="Users to test",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).pack(side="left", padx=(0, 6))
        user_count_combo = ttk.Combobox(
            user_count_frame,
            textvariable=self.user_count_var,
            values=list(range(1, MAX_SNMP_USERS + 1)),
            state="readonly",
            width=4,
        )
        user_count_combo.pack(side="left")
        user_count_combo.bind("<<ComboboxSelected>>", self._on_user_count_changed)

        credential_area = tk.Frame(credentials_panel, bg=PANEL_BG)
        credential_area.grid(row=1, column=0, columnspan=2, sticky="ew")
        credential_area.grid_columnconfigure(0, weight=1)

        self.credentials_canvas = tk.Canvas(
            credential_area,
            bg=PANEL_BG,
            height=160,
            highlightthickness=0,
            bd=0,
        )
        credential_scrollbar = ttk.Scrollbar(
            credential_area,
            orient="vertical",
            command=self.credentials_canvas.yview,
        )
        self.credentials_canvas.configure(yscrollcommand=credential_scrollbar.set)
        self.credentials_canvas.grid(row=0, column=0, sticky="ew")
        credential_scrollbar.grid(row=0, column=1, sticky="ns", padx=(6, 0))

        self.credentials_inner = tk.Frame(self.credentials_canvas, bg=PANEL_BG)
        self.credentials_window = self.credentials_canvas.create_window(
            (0, 0),
            window=self.credentials_inner,
            anchor="nw",
        )
        self.credentials_inner.grid_columnconfigure(0, weight=1)
        self.credentials_inner.grid_columnconfigure(1, weight=1)
        self.credentials_inner.bind(
            "<Configure>",
            lambda _event: self.credentials_canvas.configure(
                scrollregion=self.credentials_canvas.bbox("all")
            ),
        )
        self.credentials_canvas.bind(
            "<Configure>",
            lambda event: self.credentials_canvas.itemconfigure(
                self.credentials_window,
                width=event.width,
            ),
        )

        for idx, credential_vars in enumerate(self.credential_vars):
            section = self._build_credential_section(self.credentials_inner, idx, credential_vars, label_font)
            self.credential_sections.append(section)

        self._refresh_credential_sections()

        controls_panel = make_panel(2, pady=(0, 0))
        controls_panel.grid_columnconfigure(0, weight=1)
        tk.Checkbutton(
            controls_panel,
            text="Write SNMP debug log",
            variable=self.write_debug_log_var,
            bg=PANEL_BG,
            fg=TEXT_PRIMARY,
            activebackground=PANEL_BG,
            activeforeground=TEXT_PRIMARY,
            selectcolor=PANEL_BG,
            bd=0,
            highlightthickness=0,
        ).grid(row=0, column=0, sticky="w")

        btn_row = tk.Frame(controls_panel, bg=PANEL_BG)
        btn_row.grid(row=0, column=1, sticky="e")

        self.run_btn = ttk.Button(
            btn_row,
            text="Initiate Verification",
            command=self.run_in_thread,
            style="Primary.TButton",
            width=18,
            takefocus=False,
        )
        self.run_btn.pack(side="left", padx=(0, 6))

        self.stop_btn = ttk.Button(
            btn_row,
            text="Stop Process",
            command=self.request_stop,
            style="Danger.TButton",
            width=13,
            takefocus=False,
        )
        self.stop_btn.pack_forget()

        tk.Label(
            controls_panel,
            textvariable=self.status_var,
            bg=PANEL_BG,
            fg=TEXT_PRIMARY,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Progressbar(
            controls_panel,
            variable=self.progress_percent_var,
            maximum=100,
            mode="determinate",
            style="Corporate.Horizontal.TProgressbar",
        ).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 3))
        tk.Label(
            controls_panel,
            textvariable=self.progress_var,
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=("Segoe UI", 9),
            anchor="w",
        ).grid(row=3, column=0, columnspan=2, sticky="ew")

    def _build_credential_section(
        self,
        parent: tk.Widget,
        index: int,
        credential_vars: dict[str, tk.StringVar],
        label_font: tuple[str, int],
    ) -> tk.Frame:
        section = tk.Frame(
            parent,
            bg=PANEL_ALT_BG,
            highlightbackground=BORDER,
            highlightcolor=BORDER,
            highlightthickness=1,
            bd=0,
            padx=10,
            pady=8,
        )
        section.grid_columnconfigure(1, weight=1)

        tk.Label(
            section,
            text=f"SNMPv3 user {index + 1}",
            bg=PANEL_ALT_BG,
            fg=TEXT_PRIMARY,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))

        tk.Label(
            section,
            text="Username",
            bg=PANEL_ALT_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=1, column=0, sticky="w", pady=(0, 5), padx=(0, 10))
        ttk.Entry(section, textvariable=credential_vars["username"]).grid(
            row=1, column=1, sticky="ew", pady=(0, 5), ipady=1
        )

        tk.Label(
            section,
            text="AUTH protocol",
            bg=PANEL_ALT_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=2, column=0, sticky="w", pady=(0, 5), padx=(0, 10))
        ttk.Combobox(
            section,
            textvariable=credential_vars["auth_proto"],
            values=list(AUTH_PROTOCOLS.keys()),
            state="readonly",
            width=12,
        ).grid(row=2, column=1, sticky="ew", pady=(0, 5))

        tk.Label(
            section,
            text="PRIV protocol",
            bg=PANEL_ALT_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=3, column=0, sticky="w", pady=(0, 5), padx=(0, 10))
        ttk.Combobox(
            section,
            textvariable=credential_vars["priv_proto"],
            values=list(PRIV_PROTOCOLS.keys()),
            state="readonly",
            width=12,
        ).grid(row=3, column=1, sticky="ew", pady=(0, 5))

        tk.Label(
            section,
            text="AUTH password",
            bg=PANEL_ALT_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=4, column=0, sticky="w", pady=(0, 5), padx=(0, 10))
        ttk.Entry(section, textvariable=credential_vars["auth"], show="*").grid(
            row=4, column=1, sticky="ew", pady=(0, 5), ipady=1
        )

        tk.Label(
            section,
            text="PRIV password",
            bg=PANEL_ALT_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=5, column=0, sticky="w", padx=(0, 10))
        ttk.Entry(section, textvariable=credential_vars["priv"], show="*").grid(
            row=5, column=1, sticky="ew", ipady=1
        )

        return section

    def _get_user_count(self) -> int:
        try:
            return max(1, min(MAX_SNMP_USERS, int(self.user_count_var.get())))
        except (TypeError, ValueError, tk.TclError):
            self.user_count_var.set(1)
            return 1

    def _on_user_count_changed(self, _event=None):
        self._refresh_credential_sections()

    def _refresh_credential_sections(self):
        visible_count = self._get_user_count()

        for idx, section in enumerate(self.credential_sections):
            section.grid_forget()
            if idx < visible_count:
                row = idx // 2
                column = idx % 2
                section.grid(
                    row=row,
                    column=column,
                    sticky="nsew",
                    padx=(0, 8) if column == 0 else (8, 0),
                    pady=(0, 8),
                )

        if hasattr(self, "credentials_canvas"):
            self.credentials_canvas.yview_moveto(0)
            self.credentials_canvas.configure(scrollregion=self.credentials_canvas.bbox("all"))

    def browse_file(self):
        path = filedialog.askopenfilename(
            title="Select Excel workbook",
            filetypes=[("Excel workbooks", "*.xlsx")],
        )
        if path:
            self.file_path_var.set(path)
            self.status_var.set("Ready. Enter credentials and start verification.")

    def _toggle_buttons_running(self, running: bool):
        def _update():
            if running:
                self.run_btn.state(["disabled"])
                self.stop_btn.pack(side="left")
            else:
                self.run_btn.state(["!disabled"])
                self.stop_btn.pack_forget()
        self.after(0, _update)

    def run_in_thread(self):
        file_path = self.file_path_var.get().strip()
        credential_configs: list[CredentialConfig] = []

        if not file_path:
            messagebox.showerror("Missing file", "Please select an Excel file.")
            return

        if not file_path.lower().endswith(".xlsx"):
            messagebox.showerror("Unsupported file", "Please select an .xlsx workbook.")
            return

        if not os.path.exists(file_path):
            messagebox.showerror("Missing file", "The selected workbook could not be found.")
            return

        for idx in range(self._get_user_count()):
            credential_vars = self.credential_vars[idx]
            username = credential_vars["username"].get().strip()
            auth_password = credential_vars["auth"].get().strip()
            priv_password = credential_vars["priv"].get().strip()
            auth_proto = credential_vars["auth_proto"].get().strip()
            priv_proto = credential_vars["priv_proto"].get().strip()

            if not username:
                messagebox.showerror("Missing username", f"Please enter a username for SNMPv3 user {idx + 1}.")
                return
            if not auth_password or not priv_password:
                messagebox.showerror(
                    "Missing credentials",
                    f"Please enter AUTH and PRIV passwords for SNMPv3 user {idx + 1}.",
                )
                return

            credential_configs.append(
                CredentialConfig(
                    username=username,
                    auth_password=auth_password,
                    priv_password=priv_password,
                    auth_proto=auth_proto,
                    priv_proto=priv_proto,
                )
            )

        normalized_usernames = [c.username.casefold() for c in credential_configs]
        if len(set(normalized_usernames)) != len(normalized_usernames):
            messagebox.showerror("Duplicate usernames", "Each SNMPv3 username must be unique.")
            return

        config = RunConfig(
            file_path=file_path,
            credentials=tuple(credential_configs),
            write_debug_log=self.write_debug_log_var.get(),
        )

        self.stop_requested.clear()
        self._toggle_buttons_running(True)

        self.status_var.set("Running verification...")
        self.progress_var.set("")
        self.progress_percent_var.set(0)
        threading.Thread(target=self.process_file, args=(config,), daemon=True).start()

    def request_stop(self):
        self.stop_requested.set()
        self.status_var.set("Stop requested... generating partial report.")
    
    def process_file(self, config: RunConfig):
        debug_lines = []
        try:
            in_path = config.file_path
            df = pd.read_excel(in_path, engine="openpyxl")

            ip_col = find_ip_address_column(df)

            # Output columns
            reach_col = "Reachability"
            snmp_cols = {
                credential.username: f"({credential.username}) SNMP Status"
                for credential in config.credentials
            }

            for c in [reach_col, *snmp_cols.values()]:
                if c not in df.columns:
                    df[c] = ""

            total = len(df)

            def save_partial_report():
                out_path = self._output_path(in_path, partial=True)
                self._save_report(df, debug_lines, out_path, config.write_debug_log, config.credentials)
                self._ui_stopped(out_path, config.write_debug_log)

            for idx in range(total):
                if self.stop_requested.is_set():
                    save_partial_report()
                    return

                ip_val = df.at[idx, ip_col]
                ip = "" if pd.isna(ip_val) else str(ip_val).strip()

                self._ui_progress(idx + 1, total, ip)

                if not is_probably_ip(ip):
                    df.at[idx, reach_col] = "not Reachable"
                    for snmp_col in snmp_cols.values():
                        df.at[idx, snmp_col] = "SNMP Communication Not Successful"
                    if config.write_debug_log:
                        debug_lines.append(
                            f"{ip}\tPING=INVALID\t"
                            + "\t".join("NOT_TESTED:Invalid IP" for _credential in config.credentials)
                        )
                    continue

                reachable = ping_ip(ip)
                df.at[idx, reach_col] = "Reachable" if reachable else "not Reachable"

                if self.stop_requested.is_set():
                    save_partial_report()
                    return

                debug_parts = [f"{ip}\tPING={'OK' if reachable else 'FAIL'}"]

                for credential in config.credentials:
                    snmp_ok, snmp_detail = snmp_test_v3_credentials(
                        credential.username,
                        credential.auth_password,
                        credential.priv_password,
                        ip,
                        auth_proto_name=credential.auth_proto,
                        priv_proto_name=credential.priv_proto,
                        stop_requested=self.stop_requested,
                    )
                    df.at[idx, snmp_cols[credential.username]] = (
                        "SNMP Success" if snmp_ok else "SNMP Communication Not Successful"
                    )

                    if config.write_debug_log:
                        debug_parts.append(
                            f"{credential.username}({credential.auth_proto}/{credential.priv_proto})="
                            f"{'OK' if snmp_ok else 'FAIL'}:{snmp_detail}"
                        )

                    if self.stop_requested.is_set():
                        if config.write_debug_log:
                            debug_lines.append("\t".join(debug_parts))
                        save_partial_report()
                        return

                if config.write_debug_log:
                    debug_lines.append("\t".join(debug_parts))

            out_path = self._output_path(in_path, partial=False)
            self._save_report(df, debug_lines, out_path, config.write_debug_log, config.credentials)
            self._ui_done(out_path, config.write_debug_log)

        except Exception as e:
            self._ui_error(str(e))

        finally:
            self._toggle_buttons_running(False)

    def _save_report(
        self,
        df: pd.DataFrame,
        debug_lines: list[str],
        out_path: str,
        write_debug_log: bool,
        credentials: tuple[CredentialConfig, ...],
    ):
        df.to_excel(out_path, index=False)

        if write_debug_log:
            log_path = self._debug_log_path(out_path)
            with open(log_path, "w", encoding="utf-8") as f:
                user_headers = "\t".join(f"{credential.username}_RESULT" for credential in credentials)
                f.write(f"IP\tPING\t{user_headers}\n")
                for line in debug_lines:
                    f.write(line + "\n")

    def _output_path(self, in_path: str, partial: bool) -> str:
        base_dir = os.path.dirname(in_path)
        base_name = os.path.splitext(os.path.basename(in_path))[0]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = "PARTIAL" if partial else "FINAL"
        return os.path.join(base_dir, f"{base_name}_SNMP_RESULTS_{suffix}_{ts}.xlsx")

    def _debug_log_path(self, out_path: str) -> str:
        base_dir = os.path.dirname(out_path)
        base_name = os.path.splitext(os.path.basename(out_path))[0]
        return os.path.join(base_dir, f"{base_name}_DEBUG.log")

    def _ui_progress(self, current: int, total: int, ip: str):
        def _update():
            percent = 0 if total <= 0 else round((current / total) * 100, 1)
            self.progress_percent_var.set(percent)
            self.progress_var.set(f"Processing {current}/{total}  |  IP: {ip}")
        self.after(0, _update)

    def _ui_done(self, out_path: str, write_debug_log: bool):
        def _update():
            self.status_var.set("Done.")
            msg = f"Output saved to: {out_path}"
            self.progress_percent_var.set(100)
            if write_debug_log:
                msg += "  (Debug log also saved)"
            self.progress_var.set(msg)
            messagebox.showinfo("Completed", f"Processing completed.\n\nSaved:\n{out_path}")
        self.after(0, _update)

    def _ui_stopped(self, out_path: str, write_debug_log: bool):
        def _update():
            self.status_var.set("Stopped by user.")
            msg = f"Partial output saved to: {out_path}"
            if write_debug_log:
                msg += "  (Debug log also saved)"
            self.progress_var.set(msg)
            messagebox.showinfo("Stopped", f"Stopped by user.\n\nPartial report saved:\n{out_path}")
        self.after(0, _update)

    def _ui_error(self, msg: str):
        def _update():
            self.status_var.set("Error.")
            self.progress_var.set("")
            messagebox.showerror("Error", msg)
        self.after(0, _update)
    

if __name__ == "__main__":
    # Requirements (for development machine only):
    #   pip install pandas openpyxl pysnmp
    app = App()
    app.mainloop()
