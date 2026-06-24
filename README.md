# Online Data Monitoring and Predictive Alert System for Industrial Ethernet Networks

This project is a FastAPI + React dashboard for monitoring Industrial Ethernet traffic in real time and predicting possible network faults before they become critical.

It was built to analyze both **Plant Network** and **Control Network** traffic, whether the data comes from an uploaded `PCAPNG` file or a live Ethernet capture. The dashboard shows health trends, alert severity, charts, and fault indicators in one place.

## Problem Statement

Industrial Ethernet networks are the communication backbone of modern automation systems. When traffic becomes abnormal, devices stop responding, or switching behavior changes unexpectedly, the problem is often noticed only after it starts affecting plant operations.

The main challenge is that manual monitoring is slow and reactive. Without one centralized view, it is difficult to catch early warning signs such as packet loss, ARP issues, topology changes, traffic bursts, or device silence before they turn into a bigger fault.

## How This Solution Helps

This dashboard gives a centralized way to watch network health in real time and detect early signs of failure before they become critical.

- It analyzes both `PN` and `CN` traffic separately so issues can be tracked more clearly.
- It supports live capture as well as uploaded `PCAPNG` files for flexible testing and analysis.
- It uses monitoring parameters like jitter, packet loss, ARP behavior, STP changes, and traffic bursts to spot unusual patterns early.
- It shows alerts in four severity levels so the user can quickly understand how serious an issue is.
- It provides charts, baselines, mute controls, and acknowledgements to make troubleshooting faster and more practical.

## Key Parameters

These are the main monitoring parameters used in the project and why they matter:

- `Device Silence / Inactivity` - flags devices that stop sending traffic for too long.
- `Switch Heartbeat Timing` - helps detect delayed or missing switch/device heartbeat messages.
- `Traffic Burst / Drop` - identifies sudden spikes or drops in traffic that may indicate congestion or failure.
- `Flow Timing (Jitter)` - shows unstable packet timing for repeated flows.
- `Packet Loss Estimation` - estimates missing packets and highlights unreliable links.
- `Broadcast-to-Unicast Ratio` - helps detect floods, loops, or abnormal broadcast-heavy traffic.
- `STP Topology Change Rate` - tracks frequent switching topology changes.
- `STP Root Bridge Tracking` - shows when the spanning-tree root changes.
- `STP Path Cost Tracking` - shows route/path changes inside the switching network.
- `ARP Ghost-Target Repeat Rate` - detects repeated ARP requests for addresses that do not reply.
- `Gratuitous ARP Events` - helps identify device resets, boot events, or address announcements.

These parameters are useful because they give early signs of link failure, switch issues, congestion, packet loss, topology changes, and ARP-related communication problems.

## Features

- Real-time monitoring for both `PN` and `CN`
- Supports uploaded `PCAPNG` files and live Ethernet capture
- Separate monitoring and alert handling for each channel
- Four alert levels: `Normal`, `Advisory`, `Degraded`, and `Critical`
- Visual charts and health indicators for network behavior
- Audio and visual alerts for critical events
- Ability to pause, resume, restart, stop, and clear monitoring
- Alert acknowledgement and mute controls
- Auto-adjusting baselines and thresholds for different network conditions

## How To Run

```bash
pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
python app.py
```
