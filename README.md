# Predictive Industrial Network Fault Dashboard

A FastAPI + React dashboard for analyzing industrial network captures and highlighting possible fault patterns from PN and CN traffic.

## What to commit to GitHub

Keep the source and config files:

- `app.py`
- `backend/`
- `frontend/src/`
- `frontend/index.html`
- `frontend/package.json`
- `frontend/package-lock.json`
- `frontend/tailwind.config.cjs`
- `frontend/postcss.config.cjs`
- `requirements.txt`
- `hj.pcapng` and `new.pcapng` only if you want sample captures in the repo

## Do not commit

- `frontend/node_modules/`
- `frontend/dist/`
- `backend/__pycache__/`
- `__pycache__/`
- `data/uploads/`
- `data/dashboard.sqlite3`

## Run

```bash
pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
python app.py
```

The app will be available on `http://127.0.0.1:8000`.

## Short Summary

The backend serves the API, stores runtime data, and handles uploaded or live packet captures. The frontend shows the dashboard, charts, alerts, and fault analysis for the PN and CN channels.
