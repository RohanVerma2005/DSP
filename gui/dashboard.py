import tkinter as tk
from tkinter import ttk, scrolledtext
import time
from typing import Dict, Any, Optional

from gui.radar_canvas import RadarCanvas

class V2VDashboard:
    """Live graphical telemetry, moving-map radar, and security monitor for V2V protocol."""

    def __init__(self, root: tk.Tk, trigger_attack_cb=None):
        self.root = root
        self.root.title("Secure V2V Protocol - Security Operations Center & Radar")
        self.root.geometry("1200x740")
        self.root.configure(bg="#1e1e2e")

        self.trigger_attack_cb = trigger_attack_cb

        # Counters
        self.total_received = 0
        self.total_accepted = 0
        self.total_dropped = 0

        self._build_ui()

    def _build_ui(self):
        # Header
        header = tk.Label(
            self.root,
            text="VEHICULAR PROTOCOL AUDIT & RADAR MONITOR",
            font=("Segoe UI", 16, "bold"),
            bg="#1e1e2e",
            fg="#cdd6f4",
            pady=8
        )
        header.pack(fill=tk.X)

        # Metrics Bar
        metrics_frame = tk.Frame(self.root, bg="#181825", pady=8)
        metrics_frame.pack(fill=tk.X, padx=15, pady=4)

        self.lbl_total = tk.Label(metrics_frame, text="Packets Received: 0", font=("Consolas", 11), bg="#181825", fg="#89b4fa")
        self.lbl_total.pack(side=tk.LEFT, expand=True)

        self.lbl_accepted = tk.Label(metrics_frame, text="Verified (Accepted): 0", font=("Consolas", 11, "bold"), bg="#181825", fg="#a6e3a1")
        self.lbl_accepted.pack(side=tk.LEFT, expand=True)

        self.lbl_dropped = tk.Label(metrics_frame, text="Attacks Neutralized: 0", font=("Consolas", 11, "bold"), bg="#181825", fg="#f38ba8")
        self.lbl_dropped.pack(side=tk.LEFT, expand=True)

        # Adversary Control Panel
        ctrl_frame = tk.LabelFrame(self.root, text=" Interactive Adversary Injection ", font=("Segoe UI", 9, "bold"), bg="#1e1e2e", fg="#fab387", padx=8, pady=6)
        ctrl_frame.pack(fill=tk.X, padx=15, pady=4)

        btn_tamper = tk.Button(ctrl_frame, text="Inject Tampering Attack", bg="#f38ba8", fg="#11111b", font=("Segoe UI", 9, "bold"), command=lambda: self._trigger("TAMPER"))
        btn_tamper.pack(side=tk.LEFT, padx=6, expand=True)

        btn_replay = tk.Button(ctrl_frame, text="Inject Replay Attack", bg="#fab387", fg="#11111b", font=("Segoe UI", 9, "bold"), command=lambda: self._trigger("REPLAY"))
        btn_replay.pack(side=tk.LEFT, padx=6, expand=True)

        btn_sybil = tk.Button(ctrl_frame, text="Inject Sybil Attack", bg="#f9e2af", fg="#11111b", font=("Segoe UI", 9, "bold"), command=lambda: self._trigger("SYBIL"))
        btn_sybil.pack(side=tk.LEFT, padx=6, expand=True)

        btn_teleport = tk.Button(ctrl_frame, text="Inject Teleportation Anomaly", bg="#cba6f7", fg="#11111b", font=("Segoe UI", 9, "bold"), command=lambda: self._trigger("TELEPORT"))
        btn_teleport.pack(side=tk.LEFT, padx=6, expand=True)

        btn_dos = tk.Button(ctrl_frame, text="Inject DoS Flood", bg="#eba0ac", fg="#11111b", font=("Segoe UI", 9, "bold"), command=lambda: self._trigger("DOS"))
        btn_dos.pack(side=tk.LEFT, padx=6, expand=True)

        btn_rsu = tk.Button(
            ctrl_frame,
            text="RSU: Detect Black Ice Alert",
            bg="#89dceb",
            fg="#11111b",
            font=("Segoe UI", 9, "bold"),
            command=lambda: self._trigger("RSU_BLACK_ICE")
        )
        btn_rsu.pack(side=tk.LEFT, padx=6, expand=True)

        btn_unicast = tk.Button(
            ctrl_frame,
            text="ECDH: Platoon Handshake & Encrypt",
            bg="#b4befe",
            fg="#11111b",
            font=("Segoe UI", 9, "bold"),
            command=lambda: self._trigger("UNICAST_HANDSHAKE")
        )
        btn_unicast.pack(side=tk.LEFT, padx=6, expand=True)


        # Center Workspace: Left = Radar Canvas, Right = Security Console
        workspace = tk.Frame(self.root, bg="#1e1e2e")
        workspace.pack(fill=tk.BOTH, expand=True, padx=15, pady=8)

        # Radar Frame (Left)
        radar_frame = tk.LabelFrame(workspace, text=" 2D Situational Radar (Ego Center) ", font=("Segoe UI", 10, "bold"), bg="#1e1e2e", fg="#89b4fa")
        radar_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        self.radar = RadarCanvas(radar_frame, radius_meters=350.0)
        self.radar.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Log Frame (Right)
        log_frame = tk.LabelFrame(workspace, text=" Real-Time V2V Security Audit Console ", font=("Segoe UI", 10, "bold"), bg="#1e1e2e", fg="#cdd6f4")
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))

        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            bg="#11111b",
            fg="#cdd6f4",
            font=("Consolas", 9),
            wrap=tk.WORD,
            insertbackground="white"
        )
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.log_area.tag_config("ACCEPT", foreground="#a6e3a1")
        self.log_area.tag_config("DROP", foreground="#f38ba8")
        self.log_area.tag_config("INFO", foreground="#89dceb")
        self.log_area.tag_config("UNICAST", foreground="#b4befe")

    def _trigger(self, attack_type: str):
        if self.trigger_attack_cb:
            self.trigger_attack_cb(attack_type)

    def log_event(self, text: str, tag: str = "INFO"):
        def append():
            timestamp = time.strftime("[%H:%M:%S] ")
            self.log_area.insert(tk.END, timestamp + text + "\n", tag)
            self.log_area.see(tk.END)
        self.root.after(0, append)

    def update_stats(self, accepted: bool):
        def update():
            self.total_received += 1
            if accepted:
                self.total_accepted += 1
            else:
                self.total_dropped += 1

            self.lbl_total.config(text=f"Packets Received: {self.total_received}")
            self.lbl_accepted.config(text=f"Verified (Accepted): {self.total_accepted}")
            self.lbl_dropped.config(text=f"Attacks Neutralized: {self.total_dropped}")
        self.root.after(0, update)

    def plot_radar_vehicle(
        self,
        pseudo_id: str,
        ego_lat: float,
        ego_lon: float,
        target_lat: float,
        target_lon: float,
        speed_kmh: float,
        heading_deg: float,
        event_type: str,
        is_attack: bool = False
    ):
        """Thread-safe update to radar view."""
        self.root.after(
            0,
            lambda: self.radar.update_vehicle(
                pseudo_id=pseudo_id,
                ego_lat=ego_lat,
                ego_lon=ego_lon,
                target_lat=target_lat,
                target_lon=target_lon,
                speed_kmh=speed_kmh,
                heading_deg=heading_deg,
                event_type=event_type,
                is_attack=is_attack
            )
        )