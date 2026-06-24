from __future__ import annotations

import asyncio
import json
import tempfile
import time
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .config import APP_NAME, CHANNELS, CN, FRONTEND_DIST, PN, UPLOAD_DIR
from .models import FaultConfig, FaultType
from .runtime import DashboardRuntime, detect_live_interface, list_live_interfaces


runtime = DashboardRuntime()
app = FastAPI(title=APP_NAME)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
def shutdown_runtime() -> None:
    runtime.shutdown()


def _jsonable(value):
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if hasattr(value, "value"):
        return value.value
    if hasattr(value, "__dict__") and value.__class__.__module__.startswith("backend"):
        return {k: _jsonable(v) for k, v in value.__dict__.items()}
    return value


def _fault_from_payload(payload: dict | None) -> FaultConfig:
    if not payload:
        return FaultConfig()
    fault_type = FaultType(payload.get("fault_type", "none"))
    return FaultConfig(
        enabled=bool(payload.get("enabled", False)),
        fault_type=fault_type,
        source_mac=payload.get("source_mac", "") or "",
        target_ip=payload.get("target_ip", "") or "",
        flow_id=payload.get("flow_id", "") or "",
        start_elapsed=float(payload.get("start_elapsed", 1.0)),
        factor=float(payload.get("factor", 3.0)),
    )


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "name": APP_NAME, "channels": CHANNELS}


@app.get("/api/overview")
def overview() -> dict:
    return _jsonable(runtime.combined_overview())


@app.get("/api/channels/{channel}")
def channel_snapshot(channel: str) -> dict:
    if channel not in CHANNELS:
        raise HTTPException(status_code=404, detail="Unknown channel")
    return _jsonable(runtime.snapshot(channel))


@app.post("/api/channels/{channel}/fault")
def set_fault(channel: str, fault: str = Form("")) -> dict:
    if channel not in CHANNELS:
        raise HTTPException(status_code=404, detail="Unknown channel")
    fault_payload = json.loads(fault) if fault else None
    runtime.channel(channel).set_fault(_fault_from_payload(fault_payload))
    return {"ok": True, "channel": channel, "status": "fault settings saved"}


@app.post("/api/channels/{channel}/upload")
async def upload_capture(channel: str, file: UploadFile = File(...), speed_multiplier: float = Form(1.0), fault: str = Form("")) -> dict:
    if channel not in CHANNELS:
        raise HTTPException(status_code=404, detail="Unknown channel")
    suffix = Path(file.filename or "capture.pcapng").suffix.lower() or ".pcapng"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, dir=UPLOAD_DIR) as tmp:
        while chunk := await file.read(1024 * 1024):
            tmp.write(chunk)
        tmp_path = Path(tmp.name)
    await file.close()
    fault_payload = json.loads(fault) if fault else None
    runtime.upload_capture(channel, tmp_path, file.filename or tmp_path.name, speed=float(speed_multiplier), fault=_fault_from_payload(fault_payload))
    return {"ok": True, "channel": channel, "filename": file.filename or tmp_path.name, "status": "queued"}


@app.post("/api/channels/{channel}/live")
def start_live(channel: str, interface_name: str = Form(""), fault: str = Form("")) -> dict:
    if channel not in CHANNELS:
        raise HTTPException(status_code=404, detail="Unknown channel")
    fault_payload = json.loads(fault) if fault else None
    runtime.start_live(channel, interface_name, fault=_fault_from_payload(fault_payload))
    selected = detect_live_interface(interface_name or None)
    return {"ok": True, "channel": channel, "interface": selected, "status": "running"}


@app.get("/api/interfaces")
def interfaces() -> dict:
    items = list_live_interfaces()
    return {
        "items": items,
        "default": detect_live_interface(None),
    }


@app.post("/api/channels/{channel}/pause")
def pause_channel(channel: str) -> dict:
    runtime.pause(channel)
    return {"ok": True}


@app.post("/api/channels/{channel}/resume")
def resume_channel(channel: str) -> dict:
    runtime.resume(channel)
    return {"ok": True}


@app.post("/api/channels/{channel}/restart")
def restart_channel(channel: str) -> dict:
    runtime.restart(channel)
    return {"ok": True}


@app.post("/api/channels/{channel}/stop")
def stop_channel(channel: str) -> dict:
    runtime.stop(channel)
    return {"ok": True}


@app.post("/api/channels/{channel}/clear")
def clear_channel(channel: str, clear_store: bool = True) -> dict:
    if channel not in CHANNELS:
        raise HTTPException(status_code=404, detail="Unknown channel")
    snapshot = runtime.clear(channel, clear_store=clear_store)
    return _jsonable(snapshot)


@app.post("/api/channels/{channel}/alerts/{metric_id}/ack")
def acknowledge_alert(channel: str, metric_id: str) -> dict:
    ok = runtime.acknowledge_alert(channel, metric_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"ok": True}


@app.post("/api/channels/{channel}/alerts/ack-all")
def acknowledge_channel_alerts(channel: str) -> dict:
    if channel not in CHANNELS:
        raise HTTPException(status_code=404, detail="Unknown channel")
    acknowledged = runtime.acknowledge_alerts(channel)
    return {"ok": True, "channel": channel, "acknowledged": acknowledged}


@app.post("/api/alerts/ack-all")
def acknowledge_all_alerts(channel: str | None = None) -> dict:
    if channel is not None and channel not in CHANNELS:
        raise HTTPException(status_code=404, detail="Unknown channel")
    acknowledged = runtime.acknowledge_alerts(channel)
    return {"ok": True, "channel": channel or "all", "acknowledged": acknowledged}


@app.post("/api/channels/{channel}/alert-mutes/{metric_id}")
def set_alert_mute(channel: str, metric_id: str, muted: bool = False) -> dict:
    if channel not in CHANNELS:
        raise HTTPException(status_code=404, detail="Unknown channel")
    runtime.set_alert_mute(channel, metric_id, muted)
    return {"ok": True, "channel": channel, "metric_id": metric_id, "muted": bool(muted)}


@app.get("/api/alerts")
def alerts(channel: str | None = None, severity: str | None = None, metric_id: str | None = None, limit: int = 500) -> dict:
    return {"items": runtime.store.read_alerts(channel, severity, metric_id, limit).fillna("").to_dict(orient="records")}


@app.get("/api/methodology")
def methodology() -> dict:
    return {
        "title": "Methodology / Interpretation Reference",
        "limitation": "Passive capture can show symptoms, but it cannot prove the exact hardware part that failed. Physical inspection is still required.",
        "note": "Recommendations adapt based on whether one device or multiple devices are affected, because that is the clearest scope signal available from packet data.",
        "sections": [
            {
                "metric": "ARP Ghost-Target Repeat Rate",
                "explanation": "Looks for one IP or several IPs that keep being asked for but never answer. The dashboard will name the affected target when it can and will switch to shared-path advice when many targets fail together.",
                "baseline": "Rolling 10-minute average requests per minute per target.",
                "thresholds": ["Advisory: > 1.5x baseline", "Critical: > 3x baseline with zero replies observed"],
            },
            {
                "metric": "Gratuitous ARP Events",
                "explanation": "Looks for a device that keeps announcing itself on the network, which can happen during boot or reset.",
                "baseline": "Event count over a 30-minute window.",
                "thresholds": ["Advisory: 1 event", "Degraded: 3+ in 30 minutes"],
            },
            {
                "metric": "Switch Heartbeat Timing",
                "explanation": "Checks whether normal switch/device heartbeat messages keep arriving on time.",
                "baseline": "Observed interval during the first 5 minutes.",
                "thresholds": ["Advisory: gap > 1.5x expected", "Degraded: gap > 3x expected", "Critical: STP gap > 10s"],
            },
            {
                "metric": "STP Topology Change Rate",
                "explanation": "Counts how often the network reports a change in its switching path.",
                "baseline": "0-1/hour is normal.",
                "thresholds": ["Advisory: 2-3/hour", "Degraded: 4-10/hour", "Critical: >10/hour or 3 in 5 minutes"],
            },
            {
                "metric": "STP Root / Path Cost",
                "explanation": "Tracks whether the main switching root changed or whether traffic moved to a backup path.",
                "baseline": "Value established during the first 5 minutes.",
                "thresholds": ["Degraded: path-cost changes", "Critical: root bridge changes"],
            },
            {
                "metric": "Flow Timing",
                "explanation": "Checks whether a repeating flow is arriving on time, and whether the same flow is also losing packets. When both are present, the UI treats it as one link issue and points to the specific flow path.",
                "baseline": "Average jitter during the first 5 minutes.",
                "thresholds": ["Advisory: >2x baseline", "Degraded: >4x baseline for 5 minutes", "Critical: >8x baseline or flow stops"],
            },
            {
                "metric": "Packet Loss Estimation",
                "explanation": "Estimates how many packets are missing compared with how many should have arrived, and shows whether the problem is isolated to one flow or spread across several flows on the same path.",
                "baseline": "Expected count derived from the discovered periodic flow interval.",
                "thresholds": ["Advisory: 1-5%", "Degraded: 5-20%", "Critical: >20% or absent"],
            },
            {
                "metric": "Traffic Burst / Drop",
                "explanation": "Tracks sudden traffic spikes and sudden traffic drops so the advice can point to either an overloaded path or a stalled capture/source path. Byte rate can look very large because it measures total payload volume per second, and the baseline only learns from normal windows.",
                "baseline": "Rolling 10-minute median plus standard deviation baselines for bytes/sec and packets/sec.",
                "thresholds": ["Critical: traffic collapses to near zero after being active", "Critical: byte or packet rate rises far above the normal baseline", "Baselines freeze while abnormal traffic is active"],
            },
            {
                "metric": "Broadcast-to-Unicast Ratio",
                "explanation": "Compares broadcast traffic against normal one-to-one traffic to spot floods or loops. The dashboard will say whether the broadcast pattern looks concentrated on one device or spread across the active segment.",
                "baseline": "Rolling 10-minute average.",
                "thresholds": ["Advisory: >1.5x baseline", "Degraded: >2.5x baseline for 5 minutes without STP change"],
            },
            {
                "metric": "Device Silence / Inactivity",
                "explanation": "Flags a device that has stopped sending traffic for longer than expected.",
                "baseline": "Typical interval discovered from observed traffic.",
                "thresholds": ["Advisory: >2x typical interval", "Degraded: >60s", "Critical: >5 minutes"],
            },
        ],
    }


@app.get("/api/metrics/{channel}")
def metrics(channel: str) -> dict:
    if channel not in CHANNELS:
        raise HTTPException(status_code=404, detail="Unknown channel")
    return _jsonable(runtime.snapshot(channel)["metrics"])


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


@app.websocket("/ws/{channel}")
async def websocket_channel(ws: WebSocket, channel: str) -> None:
    if channel not in CHANNELS:
        await ws.close(code=1008)
        return
    await ws.accept()
    try:
        while True:
            await ws.send_json(_jsonable(runtime.snapshot(channel)))
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        return
    except Exception:
        try:
            await ws.close()
        except Exception:
            pass


if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")


@app.get("/")
def index():
    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse(
        """
        <html>
          <head><title>Predictive Industrial Network Fault Dashboard</title></head>
          <body style="font-family:sans-serif;background:#f6efe3;color:#243042;padding:2rem;">
            <h1>Frontend not built yet</h1>
            <p>The FastAPI backend is running. Build the React frontend in <code>frontend/</code> to serve the full dashboard.</p>
          </body>
        </html>
        """
    )
