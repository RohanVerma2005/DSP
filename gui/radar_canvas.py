import math
import tkinter as tk
from typing import Dict, Any, Tuple

from src.utils.spatial_utils import calculate_haversine_distance

class RadarCanvas(tk.Canvas):
    """2D Polar/Cartesian Radar Display for localized V2V situational awareness."""

    def __init__(self, master, radius_meters: float = 350.0, **kwargs):
        super().__init__(master, bg="#11111b", highlightthickness=1, highlightbackground="#313244", **kwargs)
        self.max_range_m = radius_meters
        self.center_x = 0
        self.center_y = 0
        self.scale_px_per_m = 1.0

        # Cache of remote vehicles: pseudonym_id -> state dict
        self._vehicles: Dict[str, Dict[str, Any]] = {}

        self.bind("<Configure>", self._on_resize)

    def _on_resize(self, event):
        self.center_x = event.width // 2
        self.center_y = event.height // 2
        # Scale: Leave 25px margin at boundaries
        usable_radius = min(self.center_x, self.center_y) - 25
        self.scale_px_per_m = max(usable_radius / self.max_range_m, 0.1)
        self.redraw()

    def update_vehicle(
        self,
        pseudo_id: str,
        ego_lat: float,
        ego_lon: float,
        target_lat: float,
        target_lon: float,
        speed_kmh: float,
        heading_deg: float = 0.0,
        event_type: str = "BEACON",
        is_attack: bool = False
    ):
        """Calculates planar offset relative to ego-vehicle and registers the target."""
        # Convert GPS delta to local meters (flat Earth approximation for <= 1km)
        lat_dist_m = calculate_haversine_distance(ego_lat, ego_lon, target_lat, ego_lon)
        if target_lat < ego_lat:
            lat_dist_m = -lat_dist_m

        lon_dist_m = calculate_haversine_distance(ego_lat, ego_lon, ego_lat, target_lon)
        if target_lon < ego_lon:
            lon_dist_m = -lon_dist_m

        # Cartesian: +X is East (lon), +Y is North (lat)
        self._vehicles[pseudo_id] = {
            "dx_m": lon_dist_m,
            "dy_m": lat_dist_m,
            "speed_kmh": speed_kmh,
            "heading_deg": heading_deg,
            "event_type": event_type,
            "is_attack": is_attack
        }
        self.redraw()

    def redraw(self):
        """Draws rings, crosshairs, ego marker, and tracked vehicular targets."""
        self.delete("all")
        cx, cy = self.center_x, self.center_y

        if cx <= 0 or cy <= 0:
            return

        # 1. Range Rings (50m, 100m, 200m, 300m boundary)
        ranges = [50, 100, 200, 300]
        for r_m in ranges:
            r_px = r_m * self.scale_px_per_m
            color = "#f38ba8" if r_m == 300 else "#45475a"  # Red dash for 300m geocast perimeter
            dash_style = (4, 4) if r_m != 300 else (6, 2)
            self.create_oval(
                cx - r_px, cy - r_px, cx + r_px, cy + r_px,
                outline=color, dash=dash_style, width=1
            )
            # Label
            self.create_text(
                cx + 5, cy - r_px - 8,
                text=f"{r_m}m", fill="#6c7086", font=("Consolas", 8)
            )

        # 2. Reticle Crosshairs
        self.create_line(cx, 15, cx, cy * 2 - 15, fill="#313244", dash=(2, 4))
        self.create_line(15, cy, cx * 2 - 15, cy, fill="#313244", dash=(2, 4))

        # 3. Center Marker: Ego Vehicle (Car BETA)
        self.create_oval(cx - 7, cy - 7, cx + 7, cy + 7, fill="#89b4fa", outline="#cdd6f4", width=2)
        self.create_text(cx, cy + 14, text="EGO (BETA)", fill="#89b4fa", font=("Segoe UI", 8, "bold"))

        # 4. Target Vehicles
        for pid, data in self._vehicles.items():
            # Invert dy because canvas coordinates increase downwards
            vx = cx + (data["dx_m"] * self.scale_px_per_m)
            vy = cy - (data["dy_m"] * self.scale_px_per_m)

            # Determine styling based on event and validity
            if data["is_attack"]:
                fill_color = "#f38ba8"  # Attacker red/pink
                icon_symbol = "X"
            elif data["event_type"] == "EMERGENCY_BRAKE":
                fill_color = "#fab387"  # Warning orange
                icon_symbol = "!"
            elif data["event_type"] == "ROAD_HAZARD":
                fill_color = "#f9e2af"  # Yellow
                icon_symbol = "▲"
            else:
                fill_color = "#a6e3a1"  # Normal verified beacon (green)
                icon_symbol = "●"

            # Vehicle Blip
            size = 8
            self.create_oval(vx - size, vy - size, vx + size, vy + size, fill=fill_color, outline="#11111b", width=1)
            self.create_text(vx, vy, text=icon_symbol, fill="#11111b", font=("Segoe UI", 7, "bold"))

            # Heading Vector (Length proportional to speed)
            speed_ratio = min(data["speed_kmh"] / 100.0, 1.5)
            vector_len = 18 * speed_ratio
            rad = math.radians(data["heading_deg"])
            hx = vx + vector_len * math.sin(rad)
            hy = vy - vector_len * math.cos(rad)
            self.create_line(vx, vy, hx, hy, fill=fill_color, width=2, arrow=tk.LAST)

            # Label (Pseudonym & Speed)
            label = f"{pid[:12]}\n{data['speed_kmh']:.1f} km/h"
            self.create_text(vx, vy - 16, text=label, fill=fill_color, font=("Consolas", 8), justify=tk.CENTER)