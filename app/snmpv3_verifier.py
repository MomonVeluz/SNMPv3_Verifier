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
    nextCmd,
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
CREDENTIAL_VIEWPORT_EXPANDED = 190
CREDENTIAL_VIEWPORT_SCROLL = 184


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


@dataclass(frozen=True)
class WalkConfig:
    ip: str
    root_oid: str
    max_rows: int
    credential: CredentialConfig

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


def normalize_numeric_oid(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Root OID is required.")

    oid = value.strip().lstrip(".")
    if not oid or not re.match(r"^\d+(\.\d+)*$", oid):
        raise ValueError("Root OID must be numeric, for example 1.3.6.1.2.1.1.")

    return oid


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
        self.geometry("900x660")
        self.minsize(860, 660)
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

        self.walk_ip_var = tk.StringVar(value="")
        self.walk_oid_var = tk.StringVar(value="1.3.6.1.2.1.1")
        self.walk_max_rows_var = tk.IntVar(value=500)
        self.walk_username_var = tk.StringVar(value="")
        self.walk_auth_var = tk.StringVar(value="")
        self.walk_priv_var = tk.StringVar(value="")
        self.walk_auth_proto_var = tk.StringVar(value="SHA")
        self.walk_priv_proto_var = tk.StringVar(value="AES-128")
        self.walk_status_var = tk.StringVar(value="Enter device and SNMPv3 credentials.")
        self.walk_progress_var = tk.StringVar(value="")
        self.walk_stop_requested = threading.Event()
        self.walk_results: list[dict[str, str]] = []

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
        style.configure(
            "Corporate.TNotebook",
            background=WINDOW_BG,
            borderwidth=0,
        )
        style.configure(
            "Corporate.TNotebook.Tab",
            background="#EDEDED",
            foreground=TEXT_PRIMARY,
            font=("Segoe UI", 9, "bold"),
            padding=(14, 6),
        )
        style.map(
            "Corporate.TNotebook.Tab",
            background=[("selected", PANEL_BG), ("active", "#F5F5F5")],
            foreground=[("selected", ACCENT_DARK), ("active", TEXT_PRIMARY)],
        )
        style.configure(
            "Corporate.Treeview",
            background=PANEL_BG,
            fieldbackground=PANEL_BG,
            foreground=TEXT_PRIMARY,
            rowheight=23,
            borderwidth=0,
        )
        style.configure(
            "Corporate.Treeview.Heading",
            background="#ECECEC",
            foreground=TEXT_PRIMARY,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )

        section_font = ("Segoe UI", 10, "bold")
        label_font = ("Segoe UI", 9)
        header_font = ("Segoe UI Semibold", 16)

        outer = tk.Frame(self, bg=WINDOW_BG)
        outer.pack(fill="both", expand=True, padx=12, pady=12)
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(1, weight=1)

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

        notebook = ttk.Notebook(outer, style="Corporate.TNotebook")
        notebook.grid(row=1, column=0, sticky="nsew")

        verify_tab = tk.Frame(notebook, bg=WINDOW_BG)
        walk_tab = tk.Frame(notebook, bg=WINDOW_BG)
        notebook.add(verify_tab, text="Workbook Verification")
        notebook.add(walk_tab, text="SNMP Walk")

        content = tk.Frame(verify_tab, bg=WINDOW_BG)
        content.pack(fill="both", expand=True, padx=0, pady=6)
        content.grid_columnconfigure(0, weight=1)

        def make_panel(row: int, pady: tuple[int, int] = (0, 8)) -> tk.Frame:
            panel = tk.Frame(
                content,
                bg=PANEL_BG,
                highlightbackground=BORDER,
                highlightcolor=BORDER,
                highlightthickness=1,
                bd=0,
                padx=10,
                pady=8,
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
            height=CREDENTIAL_VIEWPORT_EXPANDED,
            highlightthickness=0,
            bd=0,
        )
        self.credential_scrollbar = ttk.Scrollbar(
            credential_area,
            orient="vertical",
            command=self.credentials_canvas.yview,
        )
        self.credentials_canvas.configure(yscrollcommand=self.credential_scrollbar.set)
        self.credentials_canvas.grid(row=0, column=0, sticky="ew")
        self.credential_scrollbar.grid(row=0, column=1, sticky="ns", padx=(6, 0))

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

        self._build_walk_tab(walk_tab, section_font, label_font)

    def _build_walk_tab(
        self,
        parent: tk.Widget,
        section_font: tuple[str, int, str],
        label_font: tuple[str, int],
    ):
        content = tk.Frame(parent, bg=WINDOW_BG)
        content.pack(fill="both", expand=True, padx=0, pady=8)
        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=1)
        content.grid_rowconfigure(2, weight=1)

        def make_panel(
            row: int,
            column: int = 0,
            columnspan: int = 1,
            sticky: str = "ew",
            padx: tuple[int, int] = (0, 0),
            pady: tuple[int, int] = (0, 8),
        ) -> tk.Frame:
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
            panel.grid(
                row=row,
                column=column,
                columnspan=columnspan,
                sticky=sticky,
                padx=padx,
                pady=pady,
            )
            panel.grid_columnconfigure(1, weight=1)
            return panel

        target_panel = make_panel(0, 0, padx=(0, 6))
        tk.Label(
            target_panel,
            text="Walk target",
            bg=PANEL_BG,
            fg=TEXT_PRIMARY,
            font=section_font,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        tk.Label(
            target_panel,
            text="Device IP",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        ttk.Entry(target_panel, textvariable=self.walk_ip_var).grid(
            row=1, column=1, sticky="ew", ipady=1, pady=(0, 6)
        )
        tk.Label(
            target_panel,
            text="Root OID",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=2, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        ttk.Combobox(
            target_panel,
            textvariable=self.walk_oid_var,
            values=(
                "1.3.6.1.2.1.1",
                "1.3.6.1.2.1.2.2",
                "1.3.6.1.2.1.25",
                "1.3.6.1.2.1",
            ),
        ).grid(row=2, column=1, sticky="ew", pady=(0, 6))
        tk.Label(
            target_panel,
            text="Max rows",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=3, column=0, sticky="w", padx=(0, 10))
        ttk.Combobox(
            target_panel,
            textvariable=self.walk_max_rows_var,
            values=(100, 250, 500, 1000, 2500),
            state="readonly",
            width=10,
        ).grid(row=3, column=1, sticky="w")

        credential_panel = make_panel(0, 1, padx=(6, 0))
        tk.Label(
            credential_panel,
            text="SNMPv3 credentials",
            bg=PANEL_BG,
            fg=TEXT_PRIMARY,
            font=section_font,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        tk.Label(
            credential_panel,
            text="Username",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        ttk.Entry(credential_panel, textvariable=self.walk_username_var).grid(
            row=1, column=1, sticky="ew", ipady=1, pady=(0, 6)
        )
        tk.Label(
            credential_panel,
            text="AUTH protocol",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=2, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        ttk.Combobox(
            credential_panel,
            textvariable=self.walk_auth_proto_var,
            values=list(AUTH_PROTOCOLS.keys()),
            state="readonly",
            width=12,
        ).grid(row=2, column=1, sticky="ew", pady=(0, 6))
        tk.Label(
            credential_panel,
            text="PRIV protocol",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=3, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        ttk.Combobox(
            credential_panel,
            textvariable=self.walk_priv_proto_var,
            values=list(PRIV_PROTOCOLS.keys()),
            state="readonly",
            width=12,
        ).grid(row=3, column=1, sticky="ew", pady=(0, 6))
        tk.Label(
            credential_panel,
            text="AUTH password",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=4, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        ttk.Entry(credential_panel, textvariable=self.walk_auth_var, show="*").grid(
            row=4, column=1, sticky="ew", ipady=1, pady=(0, 6)
        )
        tk.Label(
            credential_panel,
            text="PRIV password",
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=5, column=0, sticky="w", padx=(0, 10))
        ttk.Entry(credential_panel, textvariable=self.walk_priv_var, show="*").grid(
            row=5, column=1, sticky="ew", ipady=1
        )

        controls_panel = make_panel(1, 0, columnspan=2)
        controls_panel.grid_columnconfigure(0, weight=1)
        tk.Label(
            controls_panel,
            textvariable=self.walk_status_var,
            bg=PANEL_BG,
            fg=TEXT_PRIMARY,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            controls_panel,
            textvariable=self.walk_progress_var,
            bg=PANEL_BG,
            fg=TEXT_SECONDARY,
            font=("Segoe UI", 9),
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        walk_btn_row = tk.Frame(controls_panel, bg=PANEL_BG)
        walk_btn_row.grid(row=0, column=1, rowspan=2, sticky="e")
        self.walk_run_btn = ttk.Button(
            walk_btn_row,
            text="Start Walk",
            command=self.run_walk_in_thread,
            style="Primary.TButton",
            width=12,
            takefocus=False,
        )
        self.walk_run_btn.pack(side="left", padx=(0, 6))
        self.walk_stop_btn = ttk.Button(
            walk_btn_row,
            text="Stop",
            command=self.request_walk_stop,
            style="Danger.TButton",
            width=9,
            takefocus=False,
        )
        self.walk_stop_btn.pack_forget()
        self.walk_export_btn = ttk.Button(
            walk_btn_row,
            text="Export",
            command=self.export_walk_results,
            style="Secondary.TButton",
            width=10,
            takefocus=False,
        )
        self.walk_export_btn.pack(side="left")
        self.walk_export_btn.state(["disabled"])

        results_panel = make_panel(2, 0, columnspan=2, sticky="nsew", pady=(0, 0))
        results_panel.grid_rowconfigure(1, weight=1)
        tk.Label(
            results_panel,
            text="Walk results",
            bg=PANEL_BG,
            fg=TEXT_PRIMARY,
            font=section_font,
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))

        result_frame = tk.Frame(results_panel, bg=PANEL_BG)
        result_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        result_frame.grid_columnconfigure(0, weight=1)
        result_frame.grid_rowconfigure(0, weight=1)

        self.walk_tree = ttk.Treeview(
            result_frame,
            columns=("oid", "type", "value"),
            show="headings",
            height=4,
            style="Corporate.Treeview",
        )
        self.walk_tree.heading("oid", text="OID")
        self.walk_tree.heading("type", text="Type")
        self.walk_tree.heading("value", text="Value")
        self.walk_tree.column("oid", width=250, minwidth=180, anchor="w")
        self.walk_tree.column("type", width=120, minwidth=90, anchor="w")
        self.walk_tree.column("value", width=440, minwidth=220, anchor="w")

        y_scroll = ttk.Scrollbar(result_frame, orient="vertical", command=self.walk_tree.yview)
        x_scroll = ttk.Scrollbar(result_frame, orient="horizontal", command=self.walk_tree.xview)
        self.walk_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.walk_tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

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
            padx=12,
            pady=10,
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
        ).grid(row=1, column=0, sticky="w", pady=(0, 6), padx=(0, 12))
        ttk.Entry(section, textvariable=credential_vars["username"]).grid(
            row=1, column=1, sticky="ew", pady=(0, 6), ipady=2
        )

        tk.Label(
            section,
            text="AUTH protocol",
            bg=PANEL_ALT_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=2, column=0, sticky="w", pady=(0, 6), padx=(0, 12))
        ttk.Combobox(
            section,
            textvariable=credential_vars["auth_proto"],
            values=list(AUTH_PROTOCOLS.keys()),
            state="readonly",
            width=12,
        ).grid(row=2, column=1, sticky="ew", pady=(0, 6))

        tk.Label(
            section,
            text="PRIV protocol",
            bg=PANEL_ALT_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=3, column=0, sticky="w", pady=(0, 6), padx=(0, 12))
        ttk.Combobox(
            section,
            textvariable=credential_vars["priv_proto"],
            values=list(PRIV_PROTOCOLS.keys()),
            state="readonly",
            width=12,
        ).grid(row=3, column=1, sticky="ew", pady=(0, 6))

        tk.Label(
            section,
            text="AUTH password",
            bg=PANEL_ALT_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=4, column=0, sticky="w", pady=(0, 6), padx=(0, 12))
        ttk.Entry(section, textvariable=credential_vars["auth"], show="*").grid(
            row=4, column=1, sticky="ew", pady=(0, 6), ipady=2
        )

        tk.Label(
            section,
            text="PRIV password",
            bg=PANEL_ALT_BG,
            fg=TEXT_SECONDARY,
            font=label_font,
        ).grid(row=5, column=0, sticky="w", padx=(0, 12))
        ttk.Entry(section, textvariable=credential_vars["priv"], show="*").grid(
            row=5, column=1, sticky="ew", ipady=2
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
                if visible_count == 1:
                    section.grid(row=0, column=0, columnspan=2, sticky="ew", padx=0, pady=(0, 2))
                else:
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
            requires_scroll = visible_count > 2
            self.credentials_inner.update_idletasks()
            bbox = self.credentials_canvas.bbox("all")
            content_height = 0 if bbox is None else bbox[3] - bbox[1]
            expanded_height = max(CREDENTIAL_VIEWPORT_EXPANDED, content_height + 2)
            viewport_height = CREDENTIAL_VIEWPORT_SCROLL if requires_scroll else expanded_height

            self.credentials_canvas.configure(height=viewport_height)
            if requires_scroll:
                self.credential_scrollbar.grid()
            else:
                self.credential_scrollbar.grid_remove()
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

    def _toggle_walk_buttons_running(self, running: bool):
        def _update():
            if running:
                self.walk_run_btn.state(["disabled"])
                self.walk_export_btn.state(["disabled"])
                self.walk_stop_btn.pack(
                    side="left",
                    padx=(0, 6),
                    before=self.walk_export_btn,
                )
            else:
                self.walk_run_btn.state(["!disabled"])
                self.walk_stop_btn.pack_forget()
                if self.walk_results:
                    self.walk_export_btn.state(["!disabled"])
                else:
                    self.walk_export_btn.state(["disabled"])
        self.after(0, _update)

    def _clear_walk_results(self):
        self.walk_results = []
        for item_id in self.walk_tree.get_children():
            self.walk_tree.delete(item_id)
        self.walk_export_btn.state(["disabled"])

    def run_walk_in_thread(self):
        ip = self.walk_ip_var.get().strip()
        username = self.walk_username_var.get().strip()
        auth_password = self.walk_auth_var.get().strip()
        priv_password = self.walk_priv_var.get().strip()
        auth_proto = self.walk_auth_proto_var.get().strip()
        priv_proto = self.walk_priv_proto_var.get().strip()

        if not is_probably_ip(ip):
            messagebox.showerror("Invalid device IP", "Please enter a valid IPv4 address.")
            return

        try:
            root_oid = normalize_numeric_oid(self.walk_oid_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid root OID", str(exc))
            return

        try:
            max_rows = int(self.walk_max_rows_var.get())
        except (TypeError, ValueError, tk.TclError):
            messagebox.showerror("Invalid max rows", "Please select a valid maximum row count.")
            return

        if max_rows < 1:
            messagebox.showerror("Invalid max rows", "Maximum rows must be greater than zero.")
            return

        if not username:
            messagebox.showerror("Missing username", "Please enter the SNMPv3 username.")
            return
        if not auth_password or not priv_password:
            messagebox.showerror("Missing credentials", "Please enter AUTH and PRIV passwords.")
            return

        credential = CredentialConfig(
            username=username,
            auth_password=auth_password,
            priv_password=priv_password,
            auth_proto=auth_proto,
            priv_proto=priv_proto,
        )
        config = WalkConfig(
            ip=ip,
            root_oid=root_oid,
            max_rows=max_rows,
            credential=credential,
        )

        self.walk_oid_var.set(root_oid)
        self.walk_stop_requested.clear()
        self._clear_walk_results()
        self._toggle_walk_buttons_running(True)
        self.walk_status_var.set("Running SNMP walk...")
        self.walk_progress_var.set(f"Device: {ip}  |  Root OID: {root_oid}")
        threading.Thread(target=self.process_walk, args=(config,), daemon=True).start()

    def request_walk_stop(self):
        self.walk_stop_requested.set()
        self.walk_status_var.set("Stop requested...")

    def process_walk(self, config: WalkConfig):
        try:
            auth_proto = AUTH_PROTOCOLS.get(config.credential.auth_proto, usmHMACSHAAuthProtocol)
            priv_proto = PRIV_PROTOCOLS.get(config.credential.priv_proto, usmAesCfb128Protocol)
            user_data = UsmUserData(
                userName=config.credential.username,
                authKey=config.credential.auth_password,
                privKey=config.credential.priv_password,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
            target = UdpTransportTarget(
                (config.ip, SNMP_PORT),
                timeout=SNMP_TIMEOUT_SECONDS,
                retries=SNMP_RETRIES,
            )

            count = 0
            iterator = nextCmd(
                SnmpEngine(),
                user_data,
                target,
                ContextData(),
                ObjectType(ObjectIdentity(config.root_oid)),
                lexicographicMode=False,
            )

            for error_indication, error_status, error_index, var_binds in iterator:
                if self.walk_stop_requested.is_set():
                    self._ui_walk_stopped(count)
                    return

                if error_indication:
                    self._ui_walk_error(str(error_indication))
                    return

                if error_status:
                    failing_oid = "unknown"
                    if error_index and int(error_index) <= len(var_binds):
                        failing_oid = var_binds[int(error_index) - 1][0].prettyPrint()
                    self._ui_walk_error(f"{error_status.prettyPrint()} at {failing_oid}")
                    return

                for oid, value in var_binds:
                    if self.walk_stop_requested.is_set():
                        self._ui_walk_stopped(count)
                        return

                    count += 1
                    result = {
                        "Device IP": config.ip,
                        "Root OID": config.root_oid,
                        "OID": oid.prettyPrint(),
                        "Type": value.__class__.__name__,
                        "Value": value.prettyPrint(),
                    }
                    self.walk_results.append(result)
                    self._ui_walk_result(result, count)

                    if count >= config.max_rows:
                        self._ui_walk_done(count, limit_reached=True)
                        return

            self._ui_walk_done(count, limit_reached=False)

        except Exception as exc:
            self._ui_walk_error(str(exc))

        finally:
            self._toggle_walk_buttons_running(False)

    def _ui_walk_result(self, result: dict[str, str], count: int):
        def _update():
            self.walk_tree.insert(
                "",
                "end",
                values=(result["OID"], result["Type"], result["Value"]),
            )
            self.walk_progress_var.set(f"Collected {count} OID value(s).")
        self.after(0, _update)

    def _ui_walk_done(self, count: int, limit_reached: bool):
        def _update():
            if count == 0:
                self.walk_status_var.set("Completed. No OIDs returned.")
                self.walk_progress_var.set("Confirm the root OID, credentials, and device SNMP configuration.")
            elif limit_reached:
                self.walk_status_var.set("Completed at row limit.")
                self.walk_progress_var.set(f"Collected {count} OID value(s). Export is available.")
            else:
                self.walk_status_var.set("Completed.")
                self.walk_progress_var.set(f"Collected {count} OID value(s). Export is available.")
        self.after(0, _update)

    def _ui_walk_stopped(self, count: int):
        def _update():
            self.walk_status_var.set("Stopped by user.")
            if count == 0:
                self.walk_progress_var.set("No OID values were collected.")
            else:
                self.walk_progress_var.set(f"Collected {count} OID value(s). Export is available for partial results.")
        self.after(0, _update)

    def _ui_walk_error(self, msg: str):
        def _update():
            self.walk_status_var.set("SNMP walk error.")
            self.walk_progress_var.set("")
            messagebox.showerror("SNMP walk error", msg)
        self.after(0, _update)

    def export_walk_results(self):
        if not self.walk_results:
            messagebox.showinfo("No results", "Run an SNMP walk before exporting.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ip = self.walk_ip_var.get().strip().replace(".", "_") or "device"
        path = filedialog.asksaveasfilename(
            title="Export SNMP walk results",
            defaultextension=".xlsx",
            initialfile=f"SNMP_WALK_{safe_ip}_{timestamp}.xlsx",
            filetypes=[
                ("Excel workbook", "*.xlsx"),
                ("CSV file", "*.csv"),
            ],
        )
        if not path:
            return

        try:
            df = pd.DataFrame(self.walk_results)
            if path.lower().endswith(".csv"):
                df.to_csv(path, index=False)
            else:
                df.to_excel(path, index=False)
            self.walk_status_var.set("Export completed.")
            self.walk_progress_var.set(f"Saved: {path}")
            messagebox.showinfo("Export completed", f"SNMP walk results saved:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export error", str(exc))
    
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
