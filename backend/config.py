from __future__ import annotations

from pathlib import Path


APP_NAME = "Predictive Industrial Network Fault Dashboard"
ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "dashboard.sqlite3"
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"

PN = "PN"
CN = "CN"
CHANNELS = (PN, CN)

DISPLAY_REFRESH_SECONDS = 10
TICK_SECONDS = 1
WINDOW_SECONDS = 60
BASELINE_SECONDS = 300
ROLLING_BASIS_SECONDS = 600
ESCALATION_WINDOW_SECONDS = 15 * 60
RECOVERY_WINDOW_SECONDS = 5 * 60
MAX_ALERT_HISTORY = 5000
MAX_CHART_POINTS = 360

SEVERITY_ORDER = {
    "normal": 0,
    "advisory": 1,
    "degraded": 2,
    "critical": 3,
}

