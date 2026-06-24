import React, { useEffect, useMemo, useRef, useState } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const CHANNELS = ['PN', 'CN']
const PAGE_ORDER = ['overview', 'pn', 'cn', 'history', 'methodology', 'settings']
const severityRank = { normal: 0, advisory: 1, degraded: 2, critical: 3 }
const severityTone = {
  normal: { label: 'Normal', bg: 'bg-emerald-100', text: 'text-emerald-800', ring: 'ring-emerald-200' },
  advisory: { label: 'Advisory', bg: 'bg-blue-100', text: 'text-blue-800', ring: 'ring-blue-200' },
  degraded: { label: 'Degraded', bg: 'bg-amber-100', text: 'text-amber-900', ring: 'ring-amber-200' },
  critical: { label: 'Critical', bg: 'bg-rose-100', text: 'text-rose-900', ring: 'ring-rose-200' },
}
const channelAccent = {
  PN: '#224c72',
  CN: '#0f766e',
}
const severityColor = {
  normal: '#10b981',
  advisory: '#2563eb',
  degraded: '#f59e0b',
  critical: '#dc2626',
}
const sessionTone = {
  idle: { label: 'Idle', bg: 'bg-slate-100', text: 'text-slate-700', ring: 'ring-slate-200' },
  running: { label: 'Running', bg: 'bg-emerald-100', text: 'text-emerald-800', ring: 'ring-emerald-200' },
  paused: { label: 'Paused', bg: 'bg-amber-100', text: 'text-amber-900', ring: 'ring-amber-200' },
  finished: { label: 'Finished', bg: 'bg-indigo-100', text: 'text-indigo-800', ring: 'ring-indigo-200' },
}
const metricLabels = {
  arp_ghost_target_repeat: 'ARP Ghost-Target Repeat Rate',
  gratuitous_arp: 'Gratuitous ARP Events',
  switch_heartbeat: 'Switch Heartbeat Timing',
  stp_topology_changes: 'STP Topology-Change Rate',
  stp_root_path: 'STP Root / Path Cost Tracking',
  packet_loss_estimation: 'Packet Loss Estimation',
  traffic_burst: 'Traffic Burst / Drop',
  broadcast_unicast_ratio: 'Broadcast-to-Unicast Ratio',
  device_silence: 'Device Silence / Inactivity',
  'jitter:no_flows': 'Flow Timing',
}

const primaryMetricIds = [
  'arp_ghost_target_repeat',
  'gratuitous_arp',
  'switch_heartbeat',
  'stp_topology_changes',
  'stp_root_path',
  'traffic_burst',
  'broadcast_unicast_ratio',
  'packet_loss_estimation',
  'device_silence',
]

const muteableMetricIds = new Set(primaryMetricIds)

function EyeIcon({ closed = false }) {
  return closed ? (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 3l18 18" />
      <path d="M10.58 10.58A3 3 0 0 0 13.42 13.42" />
      <path d="M9.88 5.08A10.5 10.5 0 0 1 12 4c5 0 9.27 3 11 8-1 2.8-3.08 5.05-5.75 6.4" />
      <path d="M14.12 18.92A10.5 10.5 0 0 1 12 20c-5 0-9.27-3-11-8 .7-1.98 1.8-3.71 3.25-5.1" />
    </svg>
  ) : (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  )
}

function apiUrl(path) {
  return path
}

async function jsonFetch(path, options = {}) {
  const response = await fetch(apiUrl(path), {
    headers: {
      ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...(options.headers || {}),
    },
    ...options,
  })
  if (!response.ok) {
    const text = await response.text()
    throw new Error(text || response.statusText)
  }
  return response.json()
}

function postFormDataWithProgress(path, formData, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', apiUrl(path))
    xhr.responseType = 'json'
    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable) return
      onProgress?.(Math.round((event.loaded / event.total) * 100), 'uploading')
    }
    xhr.upload.onload = () => {
      onProgress?.(100, 'processing')
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.response ?? JSON.parse(xhr.responseText || '{}'))
        return
      }
      reject(new Error(xhr.response?.detail || xhr.responseText || xhr.statusText || 'Upload failed'))
    }
    xhr.onerror = () => reject(new Error('Network error during upload'))
    xhr.send(formData)
  })
}

function useWebSocketSnapshot(channel) {
  const [snapshot, setSnapshot] = useState(null)
  useEffect(() => {
    let socket
    let disposed = false
    let retry = 0
    const connect = () => {
      if (disposed) return
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${protocol}//${window.location.host}/ws/${channel}`)
      socket.onmessage = (event) => {
        try {
          setSnapshot(JSON.parse(event.data))
        } catch {
          // ignore
        }
      }
      socket.onclose = () => {
        if (disposed) return
        const delay = Math.min(3000, 400 * 2 ** retry++)
        setTimeout(connect, delay)
      }
      socket.onerror = () => socket?.close()
    }
    connect()
    return () => {
      disposed = true
      socket?.close()
    }
  }, [channel])
  return snapshot
}

function formatValue(value) {
  if (value === null || value === undefined) return 'n/a'
  if (typeof value === 'number') {
    if (Math.abs(value) >= 1000) return value.toLocaleString()
    return Number.isInteger(value) ? String(value) : value.toFixed(2)
  }
  return String(value)
}

function isMulticastIp(ip) {
  if (!ip || typeof ip !== 'string') return false
  const octet = Number(ip.split('.')[0])
  return Number.isFinite(octet) && octet >= 224 && octet <= 239
}

function isBroadcastIp(ip) {
  return ip === '255.255.255.255'
}

function formatTime(ts) {
  if (!ts) return 'n/a'
  return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function formatAgo(seconds) {
  if (seconds === null || seconds === undefined) return 'n/a'
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  const r = s % 60
  if (m < 60) return `${m}m ${r}s ago`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m ago`
}

function prettyMetricId(metricId) {
  if (!metricId) return 'n/a'
  return String(metricId).replaceAll(':', ' · ')
}

function resolveMetricLabel(metricId, fallback = '') {
  if (!metricId) return fallback || 'n/a'
  const direct = metricLabels[metricId]
  if (direct) return direct
  const prefix = String(metricId).split(':')[0]
  return metricLabels[prefix] || fallback || prettyMetricId(metricId)
}

function formatChartTime(ts) {
  if (!ts) return 'n/a'
  return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function seriesKeyForItem(item) {
  return item.flow_name || item.target_name || item.device_name || item.flow_id || item.target_ip || item.device_id || item.mac || item.root_mac || item.protocol || 'value'
}

function buildTimeSeries(series, valueKey, keySelector = seriesKeyForItem) {
  const rows = new Map()
  for (const item of series || []) {
    const ts = Number(item.ts)
    if (!Number.isFinite(ts)) continue
    const key = keySelector(item)
    const row = rows.get(ts) || { ts, tsLabel: formatChartTime(ts) }
    row[key] = item[valueKey] ?? item.current_rate ?? item.jitter_ms ?? item.loss_pct ?? item.ratio ?? item.count ?? item.path_cost ?? item.gap_seconds ?? item.last_seen_gap ?? item.value ?? 0
    if (item.baseline !== undefined) {
      row[`${key}Baseline`] = item.baseline
    }
    rows.set(ts, row)
  }
  return Array.from(rows.values()).sort((a, b) => a.ts - b.ts)
}

function buildSimpleSeries(series, valueKey, extraKeys = []) {
  return (series || [])
    .map((item) => ({
      ...item,
      ts: Number(item.ts),
      tsLabel: formatChartTime(item.ts),
      [valueKey]: item[valueKey] ?? 0,
      ...extraKeys.reduce((acc, key) => ({ ...acc, [key]: item[key] }), {}),
    }))
    .filter((item) => Number.isFinite(item.ts))
    .sort((a, b) => a.ts - b.ts)
}

function createAlarmAudio() {
  const sampleRate = 8000
  const duration = 0.7
  const frequency = 880
  const samples = Math.floor(sampleRate * duration)
  const buffer = new ArrayBuffer(44 + samples * 2)
  const view = new DataView(buffer)
  const writeString = (offset, text) => {
    for (let i = 0; i < text.length; i += 1) {
      view.setUint8(offset + i, text.charCodeAt(i))
    }
  }
  writeString(0, 'RIFF')
  view.setUint32(4, 36 + samples * 2, true)
  writeString(8, 'WAVE')
  writeString(12, 'fmt ')
  view.setUint32(16, 16, true)
  view.setUint16(20, 1, true)
  view.setUint16(22, 1, true)
  view.setUint32(24, sampleRate, true)
  view.setUint32(28, sampleRate * 2, true)
  view.setUint16(32, 2, true)
  view.setUint16(34, 16, true)
  writeString(36, 'data')
  view.setUint32(40, samples * 2, true)
  for (let i = 0; i < samples; i += 1) {
    const sample = Math.sin((2 * Math.PI * frequency * i) / sampleRate)
    view.setInt16(44 + i * 2, sample * 0.42 * 0x7fff, true)
  }
  const bytes = new Uint8Array(buffer)
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return `data:audio/wav;base64,${btoa(binary)}`
}

function Badge({ severity, children }) {
  const tone = severityTone[severity] || severityTone.normal
  return <span className={`pill ${tone.bg} ${tone.text} ${tone.ring}`}>{children || tone.label}</span>
}

function SessionBadge({ state }) {
  const tone = sessionTone[state] || sessionTone.idle
  return <span className={`pill ${tone.bg} ${tone.text} ${tone.ring}`}>{tone.label}</span>
}

function MetricCard({ channel, metric, muted, onToggleMute }) {
  const isLearning = metric.learning_state !== 'stable'
  const baselineText = isLearning ? 'Learning' : formatValue(metric.baseline)
  return (
    <div className="glass-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-bold uppercase tracking-wider text-slate-500">{metric.label}</div>
          <div className="mt-2 text-2xl font-black text-ink">{formatValue(metric.value)}</div>
        </div>
        <div className="flex items-start gap-3">
          <Badge severity={metric.severity}>{metric.severity}</Badge>
          {muteableMetricIds.has(metric.metric_id) ? (
            <button
              type="button"
              className="metric-switch"
              data-on={Boolean(muted)}
              aria-pressed={Boolean(muted)}
              title={muted ? 'Alerts muted for this metric' : 'Alerts are active for this metric'}
              onClick={() => onToggleMute?.(channel, metric.metric_id, !muted)}
            >
              <span className="metric-switch-track" aria-hidden="true">
                <span className="metric-switch-thumb" />
              </span>
              <span className="metric-switch-state">{muted ? 'On' : 'Off'}</span>
            </button>
          ) : null}
        </div>
      </div>
      {Boolean(muted) ? <div className="mt-2 text-xs font-bold uppercase tracking-wider text-slate-400">Alerts muted</div> : null}
      <div className="mt-3 text-sm text-slate-600">{metric.interpretation}</div>
      <div className="mt-2 text-xs text-slate-500">
        Baseline: {baselineText} | Confidence {metric.confidence}% | Trend {metric.trend}
      </div>
      <div className="mt-3 border-t border-black/5 pt-3 text-xs font-semibold uppercase tracking-wider text-sky-700">
        {isLearning ? 'Learning baseline' : 'Baseline stable'}
      </div>
      {isLearning ? (
        <div className="mt-1 text-[11px] text-slate-500">
          Normal readings only. Critical spikes are excluded from baseline updates.
        </div>
      ) : null}
      </div>
    )
  }

function SummaryStat({ label, value, tone = 'ink' }) {
  return (
    <div className="glass-card p-4">
      <div className="text-xs font-bold uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`mt-2 text-2xl font-black ${tone}`}>{value}</div>
    </div>
  )
}

function pivotSeries(series, valueKey) {
  const rows = new Map()
  for (const item of series || []) {
    const ts = item.ts
    if (!rows.has(ts)) rows.set(ts, { ts: new Date(ts * 1000).toLocaleTimeString([], { minute: '2-digit', second: '2-digit' }) })
    const row = rows.get(ts)
    const key = item.flow_name || item.target_name || item.device_name || item.flow_id || item.target_ip || item.device_id || item.mac || item.root_mac || 'value'
    row[key] = item[valueKey] ?? item[valueKey === 'jitter_ms' ? 'jitter_ms' : 'value'] ?? item.current_rate ?? item.ratio ?? item.count ?? 0
  }
  return Array.from(rows.values()).sort((a, b) => (a.ts > b.ts ? 1 : -1))
}

function ChartCard({ title, subtitle, children, wide = false }) {
  return (
    <div className={`glass-card min-w-0 p-4 ${wide ? 'md:col-span-2' : ''}`}>
      <div className="mb-3">
        <div className="section-title">{title}</div>
        {subtitle ? <div className="muted mt-1">{subtitle}</div> : null}
      </div>
      <div className="h-[clamp(18rem,28vh,22rem)] min-w-0">{children}</div>
    </div>
  )
}

function TrafficChart({ snapshot }) {
  const data = buildSimpleSeries(
    snapshot?.history && snapshot.history.length ? snapshot.history : [{ ts: Math.floor(Date.now() / 1000), pps: 0, bps: 0 }],
    'pps',
    ['pps', 'bps'],
  )
  return (
    <ChartCard title="Traffic Rate" subtitle="Packets/sec and bytes/sec over the rolling window" wide>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <defs>
            <linearGradient id="packetsFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#224c72" stopOpacity={0.35} />
              <stop offset="95%" stopColor="#224c72" stopOpacity={0.03} />
            </linearGradient>
            <linearGradient id="bytesFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#0f766e" stopOpacity={0.32} />
              <stop offset="95%" stopColor="#0f766e" stopOpacity={0.03} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#c9b899" opacity={0.45} />
          <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} tickFormatter={formatChartTime} />
          <YAxis />
          <Tooltip labelFormatter={(value) => formatChartTime(value)} />
          <Legend />
          <Area type="monotone" dataKey="pps" name="Packets/sec" stroke="#224c72" fill="url(#packetsFill)" strokeWidth={2.5} />
          <Area type="monotone" dataKey="bps" name="Bytes/sec" stroke="#0f766e" fill="url(#bytesFill)" strokeWidth={2.5} />
        </AreaChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}

function MultiFlowChart({ title, subtitle, series, valueKey, colorSet = ['#224c72', '#0f766e', '#b7791f', '#c05640', '#6b7280'] }) {
  const seriesData = useMemo(() => {
    const rows = buildTimeSeries(series, valueKey)
    return rows.length ? rows : [{ ts: Math.floor(Date.now() / 1000), tsLabel: formatChartTime(Date.now() / 1000), value: 0 }]
  }, [series, valueKey])
  const keys = useMemo(() => {
    const set = new Set()
    for (const row of seriesData) {
      Object.keys(row).forEach((k) => {
        if (k !== 'ts' && k !== 'tsLabel') set.add(k)
      })
    }
    return Array.from(set).slice(0, 5)
  }, [seriesData])

  return (
    <ChartCard title={title} subtitle={subtitle}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={seriesData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#c9b899" opacity={0.45} />
          <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} tickFormatter={formatChartTime} />
          <YAxis />
          <Tooltip labelFormatter={(value) => formatChartTime(value)} />
          <Legend />
          {keys.map((key, index) => (
            <Line key={key} type="monotone" dataKey={key} name={prettyMetricId(key)} stroke={colorSet[index % colorSet.length]} strokeWidth={2.5} dot={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}

function StepChart({ title, subtitle, series, valueKey }) {
  const data = useMemo(
    () =>
      buildSimpleSeries((series || []).length ? series : [{ ts: Math.floor(Date.now() / 1000), [valueKey]: 0 }], valueKey),
    [series],
  )
  return (
    <ChartCard title={title} subtitle={subtitle}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#c9b899" opacity={0.45} />
          <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} tickFormatter={formatChartTime} />
          <YAxis />
          <Tooltip labelFormatter={(value) => formatChartTime(value)} />
          <Line type="stepAfter" dataKey={valueKey} stroke="#224c72" strokeWidth={3} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}

function BurstChart({ series }) {
  const data = useMemo(
    () =>
      buildSimpleSeries(
        (series || []).length
          ? series
          : [{ ts: Math.floor(Date.now() / 1000), pps: 0, bps: 0, pps_baseline_mean: 0, bps_baseline_mean: 0 }],
        'bps',
        ['pps', 'bps', 'pps_baseline_mean', 'bps_baseline_mean', 'pps_burst', 'bps_burst'],
      ),
    [series],
  )
  return (
    <ChartCard title="Traffic Extremes" subtitle="Bytes/sec can look huge on busy links, and sharp drops are just as important as spikes">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#c9b899" opacity={0.45} />
          <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} tickFormatter={formatChartTime} />
          <YAxis />
          <Tooltip labelFormatter={(value) => formatChartTime(value)} />
          <Legend />
          <Line type="monotone" dataKey="bps" name="Bytes/sec" stroke="#0f766e" strokeWidth={3} dot={false} />
          <Line type="monotone" dataKey="bps_baseline_mean" name="Byte baseline" stroke="#b7791f" strokeWidth={2} dot={false} strokeDasharray="5 5" />
          <Line type="monotone" dataKey="pps" name="Packets/sec" stroke="#224c72" strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="pps_baseline_mean" name="Packet baseline" stroke="#6b7280" strokeWidth={2} dot={false} strokeDasharray="3 5" />
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}

function JitterTimeChart({ series }) {
  const data = useMemo(() => {
    const rows = new Map()
    for (const item of series || []) {
      const ts = Number(item.ts)
      if (!Number.isFinite(ts)) continue
      const row = rows.get(ts) || { ts, tsLabel: formatChartTime(ts), jitter_ms: 0, baseline_ms: 0 }
      row.jitter_ms = Math.max(row.jitter_ms, Number(item.jitter_ms ?? 0))
      row.baseline_ms = Math.max(row.baseline_ms, Number(item.baseline_ms ?? 0))
      rows.set(ts, row)
    }
    const fallbackTs = Math.floor(Date.now() / 1000)
    const ordered = Array.from(rows.values()).sort((a, b) => a.ts - b.ts)
    return ordered.length ? ordered : [{ ts: fallbackTs, tsLabel: formatChartTime(fallbackTs), jitter_ms: 0, baseline_ms: 0 }]
  }, [series])
  return (
    <ChartCard title="Jitter vs Time" subtitle="Peak jitter across monitored flows over the current session">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#c9b899" opacity={0.45} />
          <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} tickFormatter={formatChartTime} />
          <YAxis />
          <Tooltip labelFormatter={(value) => formatChartTime(value)} />
          <Legend />
          <Line type="monotone" dataKey="jitter_ms" name="Jitter (ms)" stroke="#224c72" strokeWidth={3} dot={false} />
          <Line type="monotone" dataKey="baseline_ms" name="Baseline (ms)" stroke="#b7791f" strokeWidth={2} dot={false} strokeDasharray="5 5" />
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}

function HeartbeatTrendChart({ series }) {
  const data = useMemo(() => buildTimeSeries(series, 'gap_seconds'), [series])
  const keys = useMemo(() => {
    const set = new Set()
    for (const row of data) {
      Object.keys(row).forEach((key) => {
        if (key !== 'ts' && key !== 'tsLabel' && !key.endsWith('Baseline')) set.add(key)
      })
    }
    return Array.from(set).slice(0, 5)
  }, [data])
  return (
    <ChartCard title="Heartbeat Trend" subtitle="Per-device heartbeat gaps over time">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#c9b899" opacity={0.45} />
          <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} tickFormatter={formatChartTime} />
          <YAxis />
          <Tooltip labelFormatter={(value) => formatChartTime(value)} />
          <Legend />
          {keys.map((key, index) => (
            <Line key={key} type="monotone" dataKey={key} name={prettyMetricId(key)} stroke={['#224c72', '#0f766e', '#b7791f', '#c05640', '#6b7280'][index % 5]} strokeWidth={2.5} dot={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}

function BarSeverityChart({ title, subtitle, series, labelKey, valueKey }) {
  const data = useMemo(() => {
    const rows = (series || []).slice(-8).reverse()
    return rows.length ? rows : [{ [labelKey]: 'No data', [valueKey]: 0, severity: 'normal' }]
  }, [series, labelKey, valueKey])
  return (
    <ChartCard title={title} subtitle={subtitle}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke="#c9b899" opacity={0.45} />
          <XAxis type="number" />
          <YAxis type="category" dataKey={labelKey} width={120} />
          <Tooltip />
          <Bar dataKey={valueKey} radius={[0, 12, 12, 0]}>
            {data.map((entry, index) => (
              <Cell key={entry[labelKey] || index} fill={severityColor[entry.severity] || '#224c72'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}

function EventTimeline({ snapshot }) {
  const rows = (snapshot?.event_timeline || []).filter((row) => !String(row.metric_id || '').startsWith('jitter:'))
  return (
    <div className="glass-card p-4">
      <div className="section-title">Event Timeline</div>
      <div className="muted mt-1">Severity bars by metric over the current session.</div>
      <div className="mt-4 space-y-3">
        {rows.length ? rows.map((row) => (
          <div key={`${row.metric_id}-${row.timestamp}`} className="grid grid-cols-[220px_1fr_60px] items-center gap-3">
            <div className="text-sm font-semibold text-ink">{row.metric}</div>
            <div className="h-3 rounded-full bg-white/70 p-0.5">
              <div className={`h-full rounded-full`} style={{ width: `${Math.min(100, 10 + (row.duration_seconds || 0) / 10)}%`, background: severityColor[row.severity] || '#224c72' }} />
            </div>
            <div className="text-right text-xs font-bold uppercase tracking-wider text-slate-500">{row.severity}</div>
          </div>
        )) : <div className="text-sm text-slate-500">No timeline data yet.</div>}
      </div>
    </div>
  )
}

function MetricGrid({ channel, snapshot, onToggleMute, muteOverrides }) {
  const primaryMetrics = useMemo(
    () => (snapshot?.metrics || []).filter((metric) => primaryMetricIds.includes(metric.metric_id)),
    [snapshot],
  )
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      {primaryMetrics.map((metric) => (
        <MetricCard
          channel={channel}
          key={metric.metric_id}
          metric={metric}
          muted={muteOverrides[`${channel}-${metric.metric_id}`] ?? metric.muted}
          onToggleMute={onToggleMute}
        />
      ))}
    </div>
  )
}

function ChannelHeader({ channel, snapshot, onControl, onAcknowledgeAll }) {
  return (
    <div className="glass-card p-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="pill bg-ink text-paper">{channel} CHANNEL</div>
          <h2 className="mt-3 text-3xl font-black tracking-tight text-ink">
            {channel === 'PN' ? 'Plant Network' : 'Control Network'} Dashboard
          </h2>
          <p className="mt-2 max-w-3xl text-sm text-slate-600">
            {snapshot?.source_mode || 'idle'} | {snapshot?.source_name || 'no source selected'}{snapshot?.fault_banner ? ` | ${snapshot.fault_banner}` : ''}
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <SessionBadge state={snapshot?.session_state || 'idle'} />
            <span className="pill bg-white/70 text-ink">Status updates freeze after replay finishes</span>
          </div>
        </div>
          <div className="flex flex-wrap gap-2">
            <button className="warm-btn warm-btn-secondary" onClick={() => onControl('pause')}>Pause</button>
            <button className="warm-btn warm-btn-secondary" onClick={() => onControl('resume')}>Resume</button>
            <button className="warm-btn warm-btn-secondary" onClick={() => onControl('restart')}>Restart</button>
            <button className="warm-btn warm-btn-secondary" onClick={() => onControl('stop')}>Stop</button>
            <button className="warm-btn warm-btn-primary" onClick={() => onAcknowledgeAll?.()} disabled={!snapshot?.alerts?.length}>
              Acknowledge {channel} Errors
            </button>
          </div>
        </div>
      <div className="mt-5 grid gap-3 md:grid-cols-4">
        <SummaryStat label="Packets" value={formatValue(snapshot?.total_packets)} />
        <SummaryStat label="Active Alerts" value={formatValue(snapshot?.alerts?.length)} tone="text-rose-700" />
        <SummaryStat label="Active Devices" value={formatValue(snapshot?.active_devices)} />
        <SummaryStat label="Overall Severity" value={(snapshot?.overall_severity || 'normal').toUpperCase()} />
      </div>
    </div>
  )
}

function ChannelPage({ channel, snapshot, onControl, onToggleMute, muteOverrides, onAcknowledgeAll }) {
  if (!snapshot) {
    return <div className="glass-card p-6">Loading {channel} snapshot...</div>
  }
  return (
    <div className="space-y-5">
        <ChannelHeader channel={channel} snapshot={snapshot} onControl={onControl} onAcknowledgeAll={onAcknowledgeAll} />
      <MetricGrid channel={channel} snapshot={snapshot} onToggleMute={onToggleMute} muteOverrides={muteOverrides} />
      <div className="grid gap-4 xl:grid-cols-2">
        <TrafficChart snapshot={snapshot} />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <JitterTimeChart series={snapshot.jitter_series} />
        <MultiFlowChart title="Jitter Trend" subtitle="Per monitored flow jitter in milliseconds" series={snapshot.jitter_series} valueKey="jitter_ms" />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <MultiFlowChart title="Packet Loss %" subtitle="Per monitored flow estimated loss" series={snapshot.loss_series} valueKey="loss_pct" />
        <MultiFlowChart title="Broadcast-to-Unicast Ratio" subtitle="Rolling ratio over the current session" series={snapshot.ratio_series} valueKey="ratio" />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <BurstChart series={snapshot.burst_series} />
        <StepChart title="STP Path Cost" subtitle="Root/path state changes" series={snapshot.stp_series} valueKey="path_cost" />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <HeartbeatTrendChart series={snapshot.heartbeat_history} />
        <MultiFlowChart title="STP Root Evolution" subtitle="Root bridge and path cost over time" series={snapshot.stp_root_series} valueKey="path_cost" />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <MultiFlowChart title="Device Silence" subtitle="Idle-gap trend for recently observed devices" series={snapshot.silence_series} valueKey="last_seen_gap" />
        <BarSeverityChart title="ARP Ghost Targets" subtitle="Top targets by current repeat rate" series={snapshot.arp_series} labelKey="target_ip" valueKey="current_rate" />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <EventTimeline snapshot={snapshot} />
      </div>
    </div>
  )
}

function CombinedOverview({ pn, cn, onGo, onAcknowledgePN, onAcknowledgeCN, onAcknowledgeAll }) {
  const totalAlerts = (pn?.alerts?.length || 0) + (cn?.alerts?.length || 0)
  const overallSeverity = [pn?.overall_severity || 'normal', cn?.overall_severity || 'normal'].sort((a, b) => severityRank[b] - severityRank[a])[0]
  const links = [
    { label: 'Open PN', page: 'pn' },
    { label: 'Open CN', page: 'cn' },
    { label: 'Review Alerts', page: 'history' },
    { label: 'Settings', page: 'settings' },
  ]
  return (
    <div className="space-y-5">
      <div className="glass-card p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="pill bg-amber-100 text-amber-900">COMBINED OVERVIEW</div>
            <h1 className="mt-3 text-4xl font-black tracking-tight text-ink">Predictive Industrial Network Fault Dashboard</h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-600">Plant Network and Control Network are analyzed independently on their own clocks, with live replay, fault injection, and alerting unified in one view.</p>
          </div>
          <Badge severity={overallSeverity}>{overallSeverity.toUpperCase()}</Badge>
        </div>
        <div className="mt-5 grid gap-3 md:grid-cols-4">
          <SummaryStat label="PN Alerts" value={pn?.alerts?.length || 0} tone="text-sky-700" />
          <SummaryStat label="CN Alerts" value={cn?.alerts?.length || 0} tone="text-teal-700" />
          <SummaryStat label="Active Alerts" value={totalAlerts} tone="text-rose-700" />
          <SummaryStat label="Overall Severity" value={overallSeverity.toUpperCase()} />
        </div>
          <div className="mt-5 flex flex-wrap gap-2">
            {links.map((link) => (
              <button key={link.page} className="warm-btn warm-btn-secondary" onClick={() => onGo(link.page)}>
                {link.label}
              </button>
            ))}
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <button className="warm-btn warm-btn-secondary" onClick={() => onAcknowledgePN?.()} disabled={!pn?.alerts?.length}>
              Acknowledge PN Errors
            </button>
            <button className="warm-btn warm-btn-secondary" onClick={() => onAcknowledgeCN?.()} disabled={!cn?.alerts?.length}>
              Acknowledge CN Errors
            </button>
            <button className="warm-btn warm-btn-primary" onClick={() => onAcknowledgeAll?.()} disabled={!totalAlerts}>
              Acknowledge All Errors
            </button>
          </div>
        </div>
        <div className="grid gap-4 xl:grid-cols-2">
          {[['PN', pn], ['CN', cn]].map(([channel, snapshot]) => (
            <div key={channel} className="glass-card p-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="pill" style={{ background: `${channelAccent[channel]}20`, color: channelAccent[channel] }}>{channel}</div>
                <div className="mt-3 text-2xl font-black text-ink">{channel === 'PN' ? 'Plant Network' : 'Control Network'}</div>
              </div>
              <Badge severity={snapshot?.overall_severity || 'normal'}>{(snapshot?.overall_severity || 'normal').toUpperCase()}</Badge>
            </div>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <SummaryStat label="Packets" value={snapshot?.total_packets || 0} />
              <SummaryStat label="Alerts" value={snapshot?.alerts?.length || 0} tone="text-rose-700" />
              <SummaryStat label="Devices" value={snapshot?.active_devices || 0} />
            </div>
            <div className="mt-4 text-sm text-slate-600">{snapshot?.source_mode || 'idle'} | {snapshot?.source_name || 'no source selected'}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function AlertRow({ alert, onAck, showAck = true }) {
  const humanLabel = resolveMetricLabel(alert.metric_id, alert.metric_label)
  return (
    <div className="glass-card h-full p-4" title={`${humanLabel} | ${prettyMetricId(alert.metric_id)}`}>
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <Badge severity={alert.severity}>{alert.severity.toUpperCase()}</Badge>
            <span className="pill bg-white/70 text-ink">{alert.channel}</span>
            <span className="pill bg-white/70 text-ink" title={alert.metric_id}>{humanLabel}</span>
          </div>
          <div className="space-y-3">
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-slate-400">What we see</div>
              <div className="text-base font-bold text-ink">{alert.metric_label}</div>
            </div>
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-slate-400">Do this first</div>
              <div className="text-base font-bold text-ink">{alert.recommendation}</div>
            </div>
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-slate-400">Why this matters</div>
              <div className="text-sm text-slate-600">{alert.interpretation}</div>
            </div>
            {alert.correlation_note ? (
              <div className="rounded-2xl border border-slate-200 bg-white/60 p-3">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-400">Support</div>
                <div className="mt-2 text-sm text-slate-600">{alert.correlation_note}</div>
              </div>
            ) : null}
            <div className="text-xs text-slate-500">
              Technical ID: <span className="font-semibold text-slate-700" title={alert.metric_id}>{prettyMetricId(alert.metric_id)}</span>
            </div>
            <div className="text-xs text-slate-500">Current: {formatValue(alert.current_value)} | Baseline: {formatValue(alert.baseline_value)} | Confidence {alert.confidence}%</div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">{alert.resolved ? 'Resolved' : 'Unresolved'} | {alert.acknowledged ? 'Acknowledged' : 'Unacknowledged'} | Last seen {formatTime(alert.last_seen)} | Active for {formatAgo(alert.duration_seconds)}</div>
          </div>
        </div>
        <div className="flex min-w-[190px] flex-col items-start gap-2 lg:items-end">
          <div className="text-xs font-semibold text-slate-500">{formatTime(alert.first_seen)}</div>
          <div className="text-sm font-bold text-slate-700">{formatAgo(alert.duration_seconds)}</div>
          {showAck && !alert.acknowledged ? (
            <button className="warm-btn warm-btn-primary" onClick={() => onAck(alert.channel, alert.metric_id)}>
              Acknowledge
            </button>
          ) : (
            <span className="pill bg-emerald-100 text-emerald-800">Acknowledged</span>
          )}
        </div>
      </div>
    </div>
  )
}

function AlertModal({ alert, onClose, onAck }) {
  if (!alert) return null
  const humanLabel = resolveMetricLabel(alert.metric_id, alert.metric_label)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4">
      <div className="glass-card w-full max-w-4xl p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="pill bg-rose-100 text-rose-900">CRITICAL ALERT</div>
            <h3 className="mt-3 text-3xl font-black text-ink">{alert.metric_label}</h3>
            <div className="mt-2 flex flex-wrap gap-2">
              <Badge severity={alert.severity}>{alert.severity.toUpperCase()}</Badge>
              <span className="pill bg-white/70 text-ink">{alert.channel}</span>
              <span className="pill bg-white/70 text-ink" title={alert.metric_id}>{humanLabel}</span>
            </div>
          </div>
          <button className="warm-btn warm-btn-secondary" onClick={onClose}>Send to Pending</button>
        </div>
        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <div className="rounded-3xl bg-white/65 p-4">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400">What we see</div>
            <div className="mt-1 text-base font-bold text-ink">{alert.metric_label}</div>
            <div className="mt-3 text-sm text-slate-600">{alert.interpretation}</div>
          </div>
          <div className="rounded-3xl bg-white/65 p-4">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400">Do this first</div>
            <div className="mt-1 text-base font-bold text-ink">{alert.recommendation}</div>
            <div className="mt-3 text-sm text-slate-600">Recommended action should be applied as soon as possible while the alert remains active.</div>
          </div>
        </div>
        {alert.correlation_note ? (
          <div className="mt-4 rounded-3xl border border-slate-200 bg-white/65 p-4">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400">Support</div>
            <div className="mt-2 text-sm text-slate-600">{alert.correlation_note}</div>
          </div>
        ) : null}
        <div className="mt-4 space-y-3">
          <div className="text-xs text-slate-500">Technical ID: <span className="font-semibold text-slate-700" title={alert.metric_id}>{prettyMetricId(alert.metric_id)}</span></div>
          <div className="text-sm text-slate-500">Current {formatValue(alert.current_value)} | Baseline {formatValue(alert.baseline_value)} | Confidence {alert.confidence}%</div>
          <div className="text-sm text-slate-500">First detected {formatTime(alert.first_seen)} | Active for {formatAgo(alert.duration_seconds)}</div>
        </div>
        <div className="mt-5 flex flex-wrap gap-2">
          {!alert.acknowledged ? (
            <button className="warm-btn warm-btn-primary" onClick={() => onAck(alert.channel, alert.metric_id)}>Acknowledge</button>
          ) : (
            <span className="pill bg-emerald-100 text-emerald-800">Already acknowledged</span>
          )}
        </div>
      </div>
    </div>
  )
}

function SettingsPage({ onChange, onClear }) {
  const [channel, setChannel] = useState('PN')
  const [uploadFile, setUploadFile] = useState(null)
  const [speed, setSpeed] = useState(10)
  const [sourceMode, setSourceMode] = useState('upload')
  const [faultType, setFaultType] = useState('none')
  const [sourceMac, setSourceMac] = useState('')
  const [targetIp, setTargetIp] = useState('')
  const [flowId, setFlowId] = useState('')
  const [startElapsed, setStartElapsed] = useState(1)
  const [factor, setFactor] = useState(3)
  const [status, setStatus] = useState('')
  const [operation, setOperation] = useState('idle')
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploadPhase, setUploadPhase] = useState('idle')
  const [showFaultInjection, setShowFaultInjection] = useState(false)

  const faultPayload = {
    enabled: faultType !== 'none',
    fault_type: faultType,
    source_mac: sourceMac,
    target_ip: targetIp,
    flow_id: flowId,
    start_elapsed: Number(startElapsed),
    factor: Number(factor),
  }

  const submitUpload = async () => {
    if (!uploadFile) {
      setStatus('Choose a capture file first.')
      return
    }
    setOperation('uploading')
    setUploadProgress(0)
    setUploadPhase('uploading')
    setStatus(`Uploading ${uploadFile.name}...`)
    try {
      const form = new FormData()
      form.append('file', uploadFile)
      form.append('speed_multiplier', String(speed))
      form.append('fault', JSON.stringify(faultPayload))
      setOperation('starting')
      await postFormDataWithProgress(`/api/channels/${channel}/upload`, form, (percent, phase) => {
        setUploadProgress(percent)
        if (phase) {
          setUploadPhase(phase)
        }
        if (phase === 'processing') {
          setStatus(`Upload finished. Starting replay for ${uploadFile.name}...`)
        } else {
          setStatus(`Uploading ${uploadFile.name}... ${percent}%`)
        }
      })
      setOperation('started')
      setUploadPhase('done')
      setUploadProgress(100)
      setStatus(`${channel} replay queued from ${uploadFile.name}.`)
      onChange?.()
    } catch (error) {
      setOperation('idle')
      setUploadPhase('error')
      setStatus(error instanceof Error ? error.message : 'Upload failed.')
    }
  }

  const submitFaultSettings = async () => {
    try {
      const form = new FormData()
      form.append('fault', JSON.stringify(faultPayload))
      await jsonFetch(`/api/channels/${channel}/fault`, { method: 'POST', body: form })
      setStatus(`${channel} fault settings sent.`)
      onChange?.()
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Unable to send fault settings.')
    }
  }

  const submitLive = async () => {
    setOperation('connecting')
    const interfaceLabel = 'Ethernet'
    setStatus(`Connecting to ${interfaceLabel}...`)
    try {
      const form = new FormData()
      form.append('fault', JSON.stringify(faultPayload))
      const response = await jsonFetch(`/api/channels/${channel}/live`, { method: 'POST', body: form })
      setOperation('started')
      setStatus(`${channel} live capture running on ${response?.interface || interfaceLabel}.`)
      onChange?.()
    } catch (error) {
      setOperation('idle')
      setStatus(error instanceof Error ? error.message : 'Live capture failed.')
    }
  }

  const clearChannel = async () => {
    const ok = window.confirm(`Clear ${channel} alerts, baselines, replay/live cache, and snapshot history?`)
    if (!ok) return
    await jsonFetch(`/api/channels/${channel}/clear?clear_store=true`, { method: 'POST' })
    onClear?.(channel)
    setStatus(`${channel} state cleared.`)
    onChange?.()
  }

  const control = async (action) => {
    await jsonFetch(`/api/channels/${channel}/${action}`, { method: 'POST' })
    setStatus(`${channel} ${action} complete.`)
    onChange?.()
  }

  return (
    <div className="space-y-5">
        <div className="glass-card p-6">
          <div className="pill bg-ink text-paper">SETTINGS</div>
          <h2 className="mt-3 text-3xl font-black text-ink">Channel source and fault injection controls</h2>
        <div className="mt-2 text-sm text-slate-600">Configure PN and CN independently with upload or Ethernet live capture, plus the three demo fault scenarios.</div>
        <div className="mt-4 flex flex-wrap gap-2">
          {CHANNELS.map((item) => (
            <button key={item} className={`warm-btn ${channel === item ? 'warm-btn-primary' : 'warm-btn-secondary'}`} onClick={() => setChannel(item)}>
              {item}
            </button>
          ))}
        </div>
      </div>

      <div className="settings-grid grid gap-5">
        <div className="glass-card min-w-0 p-5">
          <div className="section-title">Data Source</div>
          <div className="mt-4 grid gap-3">
            <label className="text-sm font-semibold text-slate-600">Mode</label>
            <select className="control-input" value={sourceMode} onChange={(e) => setSourceMode(e.target.value)}>
              <option value="upload">Upload capture</option>
              <option value="live">Live capture</option>
            </select>
              {sourceMode === 'upload' ? (
                <>
                  <label className="text-sm font-semibold text-slate-600">Capture file</label>
                  <input className="control-input" type="file" accept=".pcapng" onChange={(e) => setUploadFile(e.target.files?.[0] || null)} />
                  <label className="text-sm font-semibold text-slate-600">Replay speed</label>
                  <select className="control-input" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
                    {[1, 2, 5, 10].map((value) => <option key={value} value={value}>{value}x</option>)}
                  </select>
                  <div className="rounded-2xl bg-white/70 p-3">
                    <div className="flex items-center justify-between gap-3 text-xs font-bold uppercase tracking-wider text-slate-500">
                      <span>Upload Progress</span>
                      <span>{uploadPhase === 'processing' ? 'Processing' : `${uploadProgress}%`}</span>
                    </div>
                    <div className="progress-track mt-2">
                      <div className="progress-fill" style={{ width: `${Math.min(100, uploadProgress)}%` }} />
                    </div>
                    <div className="mt-2 text-xs text-slate-500">
                      {uploadPhase === 'processing'
                        ? 'The file has been uploaded and the replay is being prepared.'
                        : uploadPhase === 'done'
                          ? 'Upload complete.'
                          : 'Shows the file transfer percentage while the upload is in progress.'}
                    </div>
                  </div>
                  <button className="warm-btn warm-btn-primary w-full" onClick={submitUpload} disabled={operation === 'uploading' || operation === 'starting'}>
                    {operation === 'uploading' ? 'Uploading...' : operation === 'starting' ? 'Starting Replay...' : 'Upload & Start'}
                  </button>
                </>
              ) : (
                <>
                  <div className="rounded-2xl bg-white/70 px-4 py-3">
                    <div className="text-xs font-bold uppercase tracking-wider text-slate-500">Network Interface</div>
                    <div className="mt-2 text-sm font-semibold text-ink">Ethernet</div>
                    <div className="mt-2 text-xs text-slate-500">
                      Live capture always defaults to Ethernet. Other adapter types are not shown here.
                    </div>
                  </div>
                  <button className="warm-btn warm-btn-primary w-full" onClick={submitLive} disabled={operation === 'connecting'}>
                    {operation === 'connecting' ? 'Connecting...' : 'Run Ethernet'}
                  </button>
                </>
              )}
              {status ? (
                <div className="flex items-center gap-2 rounded-2xl bg-white/70 px-3 py-2 text-sm font-semibold text-slate-700">
                  <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-amber-500" />
                  <span>{status}</span>
                </div>
              ) : null}
              <div className="flex flex-wrap gap-2 pt-2">
                <button className="warm-btn warm-btn-secondary" onClick={() => control('pause')}>Pause</button>
                <button className="warm-btn warm-btn-secondary" onClick={() => control('resume')}>Resume</button>
                <button className="warm-btn warm-btn-secondary" onClick={() => control('restart')}>Restart</button>
                <button className="warm-btn warm-btn-secondary" onClick={() => control('stop')}>Stop</button>
                <button className="warm-btn warm-btn-primary" onClick={clearChannel}>Clear Alerts / Cache</button>
              </div>
          </div>
        </div>

        <div style={{ display: showFaultInjection ? 'block' : 'none' }}>
        <div className="glass-card min-w-0 p-5">
          <button className="flex w-full items-center justify-between gap-3 text-left" onClick={() => setShowFaultInjection((current) => !current)}>
            <div>
              <div className="section-title">Fault Injection</div>
              <div className="muted mt-1">Collapsed by default. Use the eye to reveal the demo fault form.</div>
            </div>
            <span className="pill bg-white/70 text-ink">
              <EyeIcon closed={!showFaultInjection} />
              {showFaultInjection ? 'Hide' : 'Show'}
            </span>
          </button>
          <div className="mt-4">
          <div className="mt-2 rounded-2xl bg-white/70 px-4 py-3 text-sm text-slate-600">
            <div className="font-semibold text-ink">What to keep here</div>
            <ul className="mt-2 space-y-1">
              <li>• `None` if you only want normal replay.</li>
              <li>• `Switch heartbeat loss`: keep `Source MAC`.</li>
              <li>• `ARP ghost spike`: keep `Target IP`.</li>
              <li>• `Jitter ramp`: keep `Flow ID` like `10.0.0.1:1234-&gt;10.0.0.2:5678`.</li>
              <li>• `Start elapsed seconds`: when the fault should begin after replay starts.</li>
              <li>• `Factor`: how strong the fault should be.</li>
            </ul>
          </div>
          <div className="mt-4 grid gap-3">
            <select className="control-input" value={faultType} onChange={(e) => setFaultType(e.target.value)}>
              <option value="none">None</option>
              <option value="heartbeat_loss">Switch heartbeat loss</option>
              <option value="jitter_ramp">Jitter ramp</option>
              <option value="arp_ghost_spike">ARP ghost spike</option>
            </select>
            <input className="control-input" value={sourceMac} onChange={(e) => setSourceMac(e.target.value)} placeholder="Source MAC for heartbeat loss" />
            <input className="control-input" value={targetIp} onChange={(e) => setTargetIp(e.target.value)} placeholder="Target IP for ARP ghost spike" />
            <input className="control-input" value={flowId} onChange={(e) => setFlowId(e.target.value)} placeholder="Flow ID for jitter ramp" />
            <div className="grid gap-3 sm:grid-cols-2">
              <input className="control-input" type="number" value={startElapsed} onChange={(e) => setStartElapsed(Number(e.target.value))} placeholder="Start elapsed seconds" />
              <input className="control-input" type="number" value={factor} onChange={(e) => setFactor(Number(e.target.value))} placeholder="Factor" />
            </div>
            <div className="rounded-2xl border border-sky-200 bg-sky-50 px-4 py-3 text-xs font-semibold uppercase tracking-wider text-sky-800">
              Save Fault Setup writes only the injection settings. Start Replay applies them to the chosen channel.
            </div>
            <div className="flex flex-wrap gap-2 pt-1">
              <button className="warm-btn warm-btn-secondary" onClick={submitFaultSettings}>
                Save Fault Setup
              </button>
            </div>
            {faultType !== 'none' ? <div className="rounded-2xl border border-amber-300 bg-amber-100 px-4 py-3 text-sm font-bold text-amber-900">SIMULATED FAULT - FOR DEMO</div> : null}
          </div>
        </div>
        </div>
        </div>
      </div>

        <div className="glass-card min-w-0 p-5">
          <div className="section-title">Status</div>
          <div className="mt-4 rounded-2xl bg-white/70 p-4 text-sm text-slate-700">
            Live capture stays on Ethernet and upload replay behavior is unchanged.
          </div>
          {status ? <div className="mt-3 text-sm font-semibold text-slate-700">{status}</div> : null}
        </div>
      </div>
    )
  }

function MethodologyPage({ methodology }) {
  if (!methodology) return <div className="glass-card p-6">Loading methodology...</div>
  return (
    <div className="space-y-5">
      <div className="glass-card p-6">
        <div className="pill bg-ink text-paper">METHODOLOGY</div>
        <h2 className="mt-3 text-3xl font-black text-ink">{methodology.title}</h2>
        <p className="mt-2 text-sm text-slate-600">{methodology.limitation}</p>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        {methodology.sections.map((section) => (
          <div key={section.metric} className="glass-card p-5">
            <div className="text-lg font-black text-ink">{section.metric}</div>
            <div className="mt-2 text-sm text-slate-600">{section.explanation}</div>
            <div className="mt-4 text-xs font-bold uppercase tracking-wider text-slate-500">Baseline</div>
            <div className="mt-1 text-sm text-slate-700">{section.baseline}</div>
            <div className="mt-4 text-xs font-bold uppercase tracking-wider text-slate-500">Thresholds</div>
            <ul className="mt-2 space-y-1 text-sm text-slate-700">
              {section.thresholds.map((item) => (
                <li key={item}>• {item}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  )
}

function HistoryPage({ alerts, refreshAlerts }) {
  const [channel, setChannel] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [metric, setMetric] = useState('all')
  const filtered = useMemo(() => {
    return (alerts || []).filter((item) => {
      if (channel !== 'all' && item.channel !== channel) return false
      if (severity !== 'all' && item.severity !== severity) return false
      if (metric !== 'all' && item.metric_id !== metric) return false
      return true
    })
  }, [alerts, channel, severity, metric])

  const metrics = useMemo(() => Array.from(new Set((alerts || []).map((item) => item.metric_id))), [alerts])
  return (
    <div className="space-y-5">
      <div className="glass-card p-5">
        <div className="section-title">Alert History</div>
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          <select className="control-input" value={channel} onChange={(e) => setChannel(e.target.value)}>
            <option value="all">All channels</option>
            {CHANNELS.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <select className="control-input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">All severities</option>
            {Object.keys(severityTone).map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <select className="control-input" value={metric} onChange={(e) => setMetric(e.target.value)}>
            <option value="all">All metrics</option>
            {metrics.map((item) => <option key={item} value={item}>{metricLabels[item] || item}</option>)}
          </select>
          <button className="warm-btn warm-btn-secondary" onClick={refreshAlerts}>Refresh</button>
        </div>
      </div>
      <div className="space-y-4">
        {filtered.length ? filtered.map((alert) => <AlertRow key={`${alert.channel}-${alert.metric_id}-${alert.ts}`} alert={alert} showAck={false} />) : <div className="glass-card p-6 text-sm text-slate-600">No alerts match the current filters.</div>}
      </div>
    </div>
  )
}

export default function App() {
  const pn = useWebSocketSnapshot('PN')
  const cn = useWebSocketSnapshot('CN')
  const [page, setPage] = useState('overview')
  const [alerts, setAlerts] = useState([])
  const [methodology, setMethodology] = useState(null)
  const [showAlertPanel, setShowAlertPanel] = useState(false)
  const [pendingCritical, setPendingCritical] = useState({})
  const [alertMuteOverrides, setAlertMuteOverrides] = useState({})
  const audioRef = useRef(null)
  const visibleAlertIds = useRef(new Set())

  const loadAlerts = async () => {
    const data = await jsonFetch('/api/alerts?limit=500')
    setAlerts(data.items || [])
  }

  useEffect(() => {
    jsonFetch('/api/overview').then(() => {
      // initial fetch to validate backend availability
    }).catch(() => {})
    loadAlerts().catch(() => {})
    jsonFetch('/api/methodology').then(setMethodology).catch(() => {})
    const timer = setInterval(() => {
      loadAlerts().catch(() => {})
    }, 3000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    setAlertMuteOverrides((current) => {
      const next = {}
      let changed = false
      for (const [key, value] of Object.entries(current)) {
        const [channel, ...metricParts] = key.split('-')
        const metricId = metricParts.join('-')
        const snapshot = channel === 'PN' ? pn : channel === 'CN' ? cn : null
        const metric = snapshot?.metrics?.find((item) => item.metric_id === metricId)
        if (metric && Boolean(metric.muted) === Boolean(value)) {
          changed = true
          continue
        }
        next[key] = value
      }
      return changed ? next : current
    })
  }, [pn, cn])

  const alertKey = (alert) => `${alert.channel}-${alert.metric_id}`

  const liveAlerts = useMemo(() => [...(pn?.alerts || []), ...(cn?.alerts || [])].filter((alert) => !alert.acknowledged), [pn, cn])
  const activeAlerts = useMemo(() => liveAlerts.filter((alert) => !pendingCritical[alertKey(alert)]).sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || (b.last_seen || 0) - (a.last_seen || 0)), [liveAlerts, pendingCritical])
  const pendingCriticalAlerts = useMemo(
    () => liveAlerts.filter((alert) => alert.severity === 'critical' && pendingCritical[alertKey(alert)]).sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0)),
    [liveAlerts, pendingCritical],
  )
  const criticalAlertQueue = useMemo(
    () => liveAlerts.filter((alert) => alert.severity === 'critical' && !pendingCritical[alertKey(alert)]).sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0)),
    [liveAlerts, pendingCritical],
  )
  const criticalAlert = criticalAlertQueue[0] || null

  useEffect(() => {
    setPendingCritical((current) => {
      const next = {}
      let changed = false
      for (const [key, value] of Object.entries(current)) {
        if (liveAlerts.some((alert) => alert.severity === 'critical' && alertKey(alert) === key)) {
          next[key] = value
        } else {
          changed = true
        }
      }
      return changed ? next : current
    })
  }, [liveAlerts])

  useEffect(() => {
    if (!criticalAlert) {
      if (audioRef.current) {
        audioRef.current.pause()
        audioRef.current.currentTime = 0
      }
      return
    }

    const key = alertKey(criticalAlert)
    if (!visibleAlertIds.current.has(key)) {
      visibleAlertIds.current.add(key)
      const permission = window.Notification?.permission
      if (permission === 'default' && window.Notification?.requestPermission) {
        window.Notification.requestPermission().catch(() => {})
      } else if (permission === 'granted') {
        new Notification('Critical alert', { body: criticalAlert.interpretation })
      }
    }
    if (!audioRef.current) {
      audioRef.current = new Audio(createAlarmAudio())
      audioRef.current.loop = true
    }
    audioRef.current.play().catch(() => {})
    return undefined
  }, [criticalAlert])

  useEffect(() => {
    if (!criticalAlert && !pendingCriticalAlerts.length) {
      visibleAlertIds.current.clear()
    }
  }, [criticalAlert, pendingCriticalAlerts.length])

  const overallSeverity = useMemo(() => {
    const values = [pn?.overall_severity || 'normal', cn?.overall_severity || 'normal']
    return values.sort((a, b) => severityRank[b] - severityRank[a])[0]
  }, [pn, cn])
  const activeCounts = useMemo(() => {
    const counts = { normal: 0, advisory: 0, degraded: 0, critical: 0 }
    for (const alert of activeAlerts) counts[alert.severity] = (counts[alert.severity] || 0) + 1
    return counts
  }, [activeAlerts])

  const acknowledge = async (channel, metricId) => {
    await jsonFetch(`/api/channels/${channel}/alerts/${metricId}/ack`, { method: 'POST' })
    visibleAlertIds.current.delete(`${channel}-${metricId}`)
    setPendingCritical((current) => {
      const next = { ...current }
      delete next[`${channel}-${metricId}`]
      return next
    })
    await loadAlerts().catch(() => {})
  }

  const acknowledgeChannelAlerts = async (channel) => {
    await jsonFetch(`/api/channels/${channel}/alerts/ack-all`, { method: 'POST' })
    setPendingCritical((current) => {
      const next = {}
      for (const [key, value] of Object.entries(current)) {
        if (!key.startsWith(`${channel}-`)) {
          next[key] = value
        } else {
          visibleAlertIds.current.delete(key)
        }
      }
      return next
    })
    await loadAlerts().catch(() => {})
  }

  const acknowledgeAllAlerts = async () => {
    await jsonFetch('/api/alerts/ack-all', { method: 'POST' })
    visibleAlertIds.current.clear()
    setPendingCritical({})
    await loadAlerts().catch(() => {})
  }

  const clearChannelState = (channel) => {
    setPendingCritical({})
    visibleAlertIds.current.clear()
    audioRef.current?.pause()
    audioRef.current = null
    setShowAlertPanel(false)
    setAlerts([])
    if (channel === 'PN' || channel === 'CN') {
      // The websocket snapshot will repopulate the page on the next tick.
    }
  }

  const control = (channel) => async (action) => {
    await jsonFetch(`/api/channels/${channel}/${action}`, { method: 'POST' })
  }

  const toggleMute = async (channel, metricId, muted) => {
    const key = `${channel}-${metricId}`
    setAlertMuteOverrides((current) => ({ ...current, [key]: muted }))
    try {
      await jsonFetch(`/api/channels/${channel}/alert-mutes/${metricId}?muted=${muted ? 'true' : 'false'}`, { method: 'POST' })
    } catch (error) {
      setAlertMuteOverrides((current) => ({ ...current, [key]: !muted }))
      console.error(error)
    }
  }

  const topSeverityTone = severityTone[overallSeverity] || severityTone.normal
  const activeSummary = `${activeAlerts.length} active${activeCounts.critical ? ` - ${activeCounts.critical} Critical` : ''}${activeCounts.degraded ? `, ${activeCounts.degraded} Degraded` : ''}${activeCounts.advisory ? `, ${activeCounts.advisory} Advisory` : ''}`

  return (
    <div className="min-h-screen w-full">
      <div className={`sticky top-0 z-40 border-b border-black/10 ${topSeverityTone.bg} bg-opacity-90 backdrop-blur`}>
        <div className="mx-auto flex w-full max-w-[1800px] flex-col gap-3 px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
            <button className="flex-1 text-left" onClick={() => setShowAlertPanel(true)}>
              <div className="flex flex-wrap items-center gap-2">
                <Badge severity={overallSeverity}>{overallSeverity.toUpperCase()}</Badge>
                <span className="pill bg-white/70 text-ink">{activeSummary}</span>
                <span className="pill bg-white/70 text-ink">{pendingCriticalAlerts.length} Pending</span>
                <span className="pill bg-white/70 text-ink">{pn?.alerts?.length || 0} PN</span>
                <span className="pill bg-white/70 text-ink">{cn?.alerts?.length || 0} CN</span>
              </div>
            </button>
            <div className="flex flex-wrap gap-2">
              <button className="warm-btn warm-btn-secondary" onClick={() => acknowledgeChannelAlerts('PN')} disabled={!pn?.alerts?.length}>
                Ack PN
              </button>
              <button className="warm-btn warm-btn-secondary" onClick={() => acknowledgeChannelAlerts('CN')} disabled={!cn?.alerts?.length}>
                Ack CN
              </button>
              <button className="warm-btn warm-btn-primary" onClick={acknowledgeAllAlerts} disabled={!activeAlerts.length}>
                Ack All
              </button>
              {PAGE_ORDER.map((item) => (
                <button key={item} className={`warm-btn ${page === item ? 'warm-btn-primary' : 'warm-btn-secondary'}`} onClick={() => setPage(item)}>
                  {item.toUpperCase()}
                </button>
              ))}
          </div>
        </div>
      </div>

      <div className="mx-auto grid w-full max-w-[1800px] gap-5 px-4 py-5 lg:grid-cols-[280px_minmax(0,1fr)]">
        <aside className="glass-card h-fit p-4 lg:sticky lg:top-[92px]">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-500">Navigation</div>
          <div className="mt-3 space-y-2">
            <button className={`nav-item w-full ${page === 'overview' ? 'nav-item-active' : 'nav-item-idle'}`} onClick={() => setPage('overview')}>
              <span>Combined Overview</span>
              <span>{(pn?.overall_severity || 'normal').toUpperCase()}</span>
            </button>
            <button className={`nav-item w-full ${page === 'pn' ? 'nav-item-active' : 'nav-item-idle'}`} onClick={() => setPage('pn')}>
              <span>Plant Network</span>
              <span>{pn?.alerts?.length || 0}</span>
            </button>
            <button className={`nav-item w-full ${page === 'cn' ? 'nav-item-active' : 'nav-item-idle'}`} onClick={() => setPage('cn')}>
              <span>Control Network</span>
              <span>{cn?.alerts?.length || 0}</span>
            </button>
            <button className={`nav-item w-full ${page === 'history' ? 'nav-item-active' : 'nav-item-idle'}`} onClick={() => setPage('history')}>
              <span>Alert History</span>
              <span>{alerts.length}</span>
            </button>
            <button className={`nav-item w-full ${page === 'methodology' ? 'nav-item-active' : 'nav-item-idle'}`} onClick={() => setPage('methodology')}>
              <span>Methodology</span>
            </button>
            <button className={`nav-item w-full ${page === 'settings' ? 'nav-item-active' : 'nav-item-idle'}`} onClick={() => setPage('settings')}>
              <span>Settings</span>
            </button>
          </div>
            <div className="mt-5 rounded-3xl bg-white/65 p-4">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-500">Quick Status</div>
              <div className="mt-3 space-y-2 text-sm text-slate-600">
                <div className="flex items-center justify-between gap-2">
                  <span>PN</span>
                  <SessionBadge state={pn?.session_state || 'idle'} />
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span>CN</span>
                  <SessionBadge state={cn?.session_state || 'idle'} />
                </div>
                <div>Backend: online</div>
              </div>
            </div>
        </aside>

        <main className="min-w-0 space-y-5">
          {page === 'overview' ? <CombinedOverview pn={pn} cn={cn} onGo={setPage} onAcknowledgePN={() => acknowledgeChannelAlerts('PN')} onAcknowledgeCN={() => acknowledgeChannelAlerts('CN')} onAcknowledgeAll={acknowledgeAllAlerts} /> : null}
          {page === 'pn' ? <ChannelPage channel="PN" snapshot={pn} onControl={control('PN')} onToggleMute={toggleMute} muteOverrides={alertMuteOverrides} onAcknowledgeAll={() => acknowledgeChannelAlerts('PN')} /> : null}
          {page === 'cn' ? <ChannelPage channel="CN" snapshot={cn} onControl={control('CN')} onToggleMute={toggleMute} muteOverrides={alertMuteOverrides} onAcknowledgeAll={() => acknowledgeChannelAlerts('CN')} /> : null}
          {page === 'history' ? <HistoryPage alerts={alerts} refreshAlerts={loadAlerts} /> : null}
          {page === 'methodology' ? <MethodologyPage methodology={methodology} /> : null}
          {page === 'settings' ? <SettingsPage onChange={loadAlerts} onClear={clearChannelState} /> : null}
        </main>
      </div>

      {showAlertPanel ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4" onClick={() => setShowAlertPanel(false)}>
          <div className="glass-card w-full max-w-5xl p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between gap-4">
              <div>
                <div className="pill bg-ink text-paper">ACTIVE ALERTS</div>
                <h3 className="mt-3 text-3xl font-black text-ink">Live alert detail popup</h3>
              </div>
              <button className="warm-btn warm-btn-secondary" onClick={() => setShowAlertPanel(false)}>Close</button>
            </div>
            <div className="mt-5 grid max-h-[72vh] gap-4 overflow-auto pr-1 md:grid-cols-2">
              {pendingCriticalAlerts.length ? (
                <div className="rounded-3xl border border-amber-200 bg-amber-50 p-4 md:col-span-2">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="section-title">Pending Alerts</div>
                    </div>
                    <span className="pill bg-amber-100 text-amber-900">{pendingCriticalAlerts.length}</span>
                  </div>
                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    {pendingCriticalAlerts.map((alert) => (
                      <AlertRow key={`${alert.channel}-${alert.metric_id}-${alert.ts}`} alert={alert} onAck={acknowledge} />
                    ))}
                  </div>
                </div>
              ) : null}
              {activeAlerts.length ? activeAlerts.map((alert) => (
                <AlertRow key={`${alert.channel}-${alert.metric_id}-${alert.ts}`} alert={alert} onAck={acknowledge} />
              )) : (
                <div className="rounded-3xl bg-white/70 p-6 text-sm text-slate-600 md:col-span-2">No active alerts right now.</div>
              )}
            </div>
          </div>
        </div>
      ) : null}

      {criticalAlert ? (
        <AlertModal
          alert={criticalAlert}
          onClose={() => {
            setPendingCritical((current) => ({ ...current, [alertKey(criticalAlert)]: Date.now() / 1000 }))
          }}
          onAck={acknowledge}
        />
      ) : null}
    </div>
  )
}
