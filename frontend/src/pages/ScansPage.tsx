import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Activity, Plus, X, ChevronRight, Terminal, Zap, Square, RefreshCw, Trash2, CheckSquare } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import { useAuthStore } from '../store/authStore'

const STATUS_COLOR: Record<string, string> = {
  queued: 'text-text-muted', running: 'text-accent-primary',
  completed: 'text-severity-low', failed: 'text-severity-critical',
  cancelled: 'text-severity-medium',
}
const STATUS_DOT: Record<string, string> = {
  queued: 'bg-text-muted', running: 'bg-accent-primary animate-pulse',
  completed: 'bg-severity-low', failed: 'bg-severity-critical',
  cancelled: 'bg-severity-medium',
}

const TOOLS = ['subfinder', 'httpx', 'nmap', 'nuclei', 'sqlmap', 'ghauri',
               'dalfox', 'ffuf', 'dirsearch', 'amass', 'dnsx', 'masscan']

// ── Live Terminal ────────────────────────────────────────────
function LiveTerminal({ scanId, initialStatus }: { scanId: string, initialStatus: string }) {
  const [lines, setLines] = useState<string[]>([])
  const [status, setStatus] = useState(initialStatus)
  const [progress, setProgress] = useState(0)
  const [connected, setConnected] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${window.location.host}/api/scans/ws/${scanId}`)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onerror = () => setLines(l => [...l, '[ERROR] WebSocket connection failed'])

    ws.onmessage = (e) => {
      const data = JSON.parse(e.data)
      switch (data.type) {
        case 'connected':
          setLines(l => [...l, `[+] Connected to scan ${scanId}`])
          break
        case 'status':
          setStatus(data.status)
          if (data.progress !== undefined) setProgress(data.progress)
          break
        case 'tool_start':
          setLines(l => [...l, ``, `[*] Running: ${data.tool} | Progress: ${data.progress}%`])
          setProgress(data.progress)
          break
        case 'tool_done':
          setLines(l => [...l,
            `[${data.success ? '+' : '-'}] ${data.tool} finished in ${data.duration?.toFixed(1)}s (exit: ${data.exit_code})`
          ])
          break
        case 'output':
          if (data.line) setLines(l => [...l, data.line])
          break
        case 'done':
          setStatus(data.status)
          setProgress(100)
          setLines(l => [...l, ``, `[=] Scan ${data.status.toUpperCase()}`])
          break
        case 'error':
          setLines(l => [...l, `[!] ${data.message}`])
          break
      }
    }

    return () => ws.close()
  }, [scanId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  return (
    <div className="flex flex-col h-full">
      {/* Terminal header */}
      <div className="flex items-center justify-between px-3 py-2 bg-bg-tertiary border-b border-border-default">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${connected ? 'bg-severity-low animate-pulse' : 'bg-text-muted'}`} />
          <span className="text-xs font-mono text-text-muted">
            {connected ? 'LIVE' : 'DISCONNECTED'} · {status.toUpperCase()} · {progress}%
          </span>
        </div>
        <span className="text-xs font-mono text-text-muted truncate max-w-xs">{scanId}</span>
      </div>

      {/* Progress bar */}
      <div className="h-0.5 bg-bg-tertiary">
        <div
          className="h-full bg-accent-primary transition-all duration-500"
          style={{ width: `${progress}%` }}
        />
      </div>

      {/* Terminal output */}
      <div className="flex-1 overflow-y-auto p-3 font-mono text-xs leading-5 bg-black text-green-400 min-h-0">
        {lines.length === 0 ? (
          <span className="text-text-muted">Waiting for output...</span>
        ) : (
          lines.map((line, i) => (
            <div key={i} className={`whitespace-pre-wrap break-all ${
              line.startsWith('[ERROR]') || line.startsWith('[-]') ? 'text-red-400' :
              line.startsWith('[+]') ? 'text-green-400' :
              line.startsWith('[*]') || line.startsWith('[=]') ? 'text-yellow-400' :
              line.startsWith('[!]') ? 'text-orange-400' :
              line.startsWith('[TIMEOUT]') ? 'text-red-500' :
              'text-green-300'
            }`}>{line || ' '}</div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ── New Scan Modal ───────────────────────────────────────────
function NewScanModal({ onClose, onSuccess }: { onClose: () => void, onSuccess: () => void }) {
  const [target, setTarget] = useState('')
  const [selectedTools, setSelectedTools] = useState<string[]>(['subfinder', 'httpx'])
  const [scanMode, setScanMode] = useState('custom')
  const [loading, setLoading] = useState(false)

  const toggleTool = (t: string) => setSelectedTools(prev =>
    prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t]
  )

  const handleSubmit = async () => {
    if (!target.trim()) { toast.error('Target harus diisi'); return }
    if (selectedTools.length === 0) { toast.error('Pilih minimal 1 tool'); return }
    setLoading(true)
    try {
      await api.post('/scans/', {
        target_value: target.trim(),
        scan_mode: scanMode,
        tools: selectedTools,
        parameters: {},
      })
      toast.success('Scan job created & queued!')
      onSuccess()
      onClose()
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Failed to create scan')
    } finally { setLoading(false) }
  }

  const QUICK_PRESETS = [
    { label: 'Recon', tools: ['subfinder', 'dnsx', 'httpx', 'amass'] },
    { label: 'Web', tools: ['httpx', 'nuclei', 'dalfox', 'ffuf'] },
    { label: 'Full', tools: ['subfinder', 'httpx', 'nmap', 'nuclei', 'ffuf'] },
  ]

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-default rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-5 border-b border-border-default sticky top-0 bg-bg-secondary">
          <h2 className="font-display font-bold text-text-primary flex items-center gap-2">
            <Zap size={18} className="text-accent-primary" /> New Scan Job
          </h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary"><X size={18} /></button>
        </div>

        <div className="p-5 space-y-5">
          <div>
            <label className="text-text-muted text-xs font-mono mb-1.5 block uppercase">Target *</label>
            <input value={target} onChange={e => setTarget(e.target.value)}
              className="input-field font-mono" placeholder="example.com / 10.0.0.1 / 10.0.0.0/24" />
          </div>

          <div>
            <label className="text-text-muted text-xs font-mono mb-2 block uppercase">Quick Presets</label>
            <div className="flex gap-2">
              {QUICK_PRESETS.map(p => (
                <button key={p.label} onClick={() => setSelectedTools(p.tools)}
                  className="btn-secondary text-xs px-3 py-1.5">{p.label}</button>
              ))}
              <button onClick={() => setSelectedTools([])}
                className="text-xs text-text-muted hover:text-text-secondary font-mono ml-auto">Clear</button>
            </div>
          </div>

          <div>
            <label className="text-text-muted text-xs font-mono mb-2 block uppercase">
              Tools ({selectedTools.length} selected)
            </label>
            <div className="grid grid-cols-3 gap-2">
              {TOOLS.map(t => (
                <button key={t} onClick={() => toggleTool(t)}
                  className={`text-xs font-mono px-2 py-2 rounded border transition-all text-left ${
                    selectedTools.includes(t)
                      ? 'bg-accent-primary bg-opacity-10 border-accent-primary text-accent-primary'
                      : 'border-border-default text-text-muted hover:border-border-muted'
                  }`}>
                  {selectedTools.includes(t) ? '✓ ' : ''}{t}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="flex gap-3 p-5 border-t border-border-default">
          <button onClick={onClose} className="btn-secondary flex-1">Cancel</button>
          <button onClick={handleSubmit} disabled={loading} className="btn-primary flex-1 flex items-center justify-center gap-2">
            <Zap size={14} /> {loading ? 'Queuing...' : 'Launch Scan'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────
export default function ScansPage() {
  const [showNew, setShowNew] = useState(false)
  const [selectedScan, setSelectedScan] = useState<any>(null)
  const queryClient = useQueryClient()

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['scans'],
    queryFn: () => api.get('/scans/').then(r => r.data),
    refetchInterval: 5000, // poll setiap 5 detik
  })

  const [selected, setSelected] = useState<Set<string>>(new Set())

  const cancelMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/scans/${id}`),
    onSuccess: () => { toast.success('Scan cancelled'); queryClient.invalidateQueries({ queryKey: ['scans'] }) },
    onError: () => toast.error('Failed to cancel'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/scans/${id}`, { params: { force: true } }),
    onSuccess: () => {
      toast.success('Scan deleted')
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      if (selectedScan?.id) setSelectedScan(null)
    },
    onError: () => toast.error('Failed to delete'),
  })

  const bulkDelete = async () => {
    if (selected.size === 0) return
    if (!confirm(`Delete ${selected.size} scan(s) permanently?`)) return
    for (const id of Array.from(selected)) {
      await api.delete(`/scans/${id}`, { params: { force: true } }).catch(() => {})
    }
    toast.success(`Deleted ${selected.size} scans`)
    setSelected(new Set())
    queryClient.invalidateQueries({ queryKey: ['scans'] })
  }

  const toggleSelect = (id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const scans = data?.items || []

  return (
    <div className="h-full flex flex-col space-y-4 animate-fade-in">
      {showNew && <NewScanModal
        onClose={() => setShowNew(false)}
        onSuccess={() => queryClient.invalidateQueries({ queryKey: ['scans'] })}
      />}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
            <Activity size={24} className="text-accent-primary" /> Scan Jobs
          </h1>
          <p className="text-text-muted text-sm font-mono mt-1">
            {isLoading ? '...' : `${data?.total || 0} total jobs`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {selected.size > 0 && (
            <button onClick={bulkDelete}
              className="flex items-center gap-2 text-sm font-mono px-3 py-2 rounded border border-severity-critical text-severity-critical hover:bg-severity-critical hover:bg-opacity-10 transition-colors">
              <Trash2 size={13} /> Delete {selected.size} selected
            </button>
          )}
          <button onClick={() => refetch()} className="btn-secondary p-2"><RefreshCw size={14} /></button>
          <button onClick={() => setShowNew(true)} className="btn-primary flex items-center gap-2">
            <Plus size={14} /> New Scan
          </button>
        </div>
      </div>

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Scan list */}
        <div className="w-80 flex-shrink-0 card overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center py-10">
              <div className="w-6 h-6 border-2 border-accent-primary border-t-transparent rounded-full animate-spin" />
            </div>
          ) : scans.length === 0 ? (
            <div className="p-6 text-center">
              <Activity size={32} className="text-text-muted mx-auto mb-2" />
              <p className="text-text-muted text-sm">No scans yet</p>
              <button onClick={() => setShowNew(true)} className="btn-primary mt-3 text-sm">
                Launch first scan
              </button>
            </div>
          ) : (
            <div className="divide-y divide-border-default">
              {scans.map((scan: any) => (
                <div
                  key={scan.id}
                  onClick={() => setSelectedScan(scan)}
                  className={`p-4 cursor-pointer hover:bg-bg-hover transition-colors group/row ${
                    selectedScan?.id === scan.id ? 'bg-bg-hover border-l-2 border-accent-primary' : ''
                  } ${selected.has(scan.id) ? 'bg-accent-primary bg-opacity-5' : ''}`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      {/* Checkbox untuk bulk select */}
                      <input type="checkbox" checked={selected.has(scan.id)}
                        onClick={e => toggleSelect(scan.id, e)}
                        onChange={() => {}}
                        className="w-3 h-3 accent-accent-primary opacity-0 group-hover/row:opacity-100 transition-opacity cursor-pointer flex-shrink-0"
                        style={selected.has(scan.id) ? {opacity: 1} : {}}
                      />
                      <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${STATUS_DOT[scan.status]}`} />
                      <span className={`text-xs font-mono font-medium ${STATUS_COLOR[scan.status]}`}>
                        {scan.status.toUpperCase()}
                      </span>
                    </div>
                    <div className="flex items-center gap-1">
                      {scan.status === 'running' && (
                        <button
                          onClick={e => { e.stopPropagation(); cancelMutation.mutate(scan.id) }}
                          className="text-severity-critical hover:opacity-70 p-0.5"
                          title="Cancel scan"
                        >
                          <Square size={11} />
                        </button>
                      )}
                      {/* Delete button - muncul saat hover */}
                      <button
                        onClick={e => { e.stopPropagation(); if(confirm('Delete this scan permanently?')) deleteMutation.mutate(scan.id) }}
                        className="text-text-muted hover:text-severity-critical p-0.5 opacity-0 group-hover/row:opacity-100 transition-all"
                        title="Delete scan"
                      >
                        <Trash2 size={11} />
                      </button>
                      <ChevronRight size={12} className="text-text-muted" />
                    </div>
                  </div>
                  <p className="font-mono text-sm text-text-primary truncate">{scan.target_value}</p>
                  <div className="flex items-center gap-1 mt-1 flex-wrap">
                    {(scan.tools || []).slice(0, 3).map((t: string) => (
                      <span key={t} className="text-xs bg-bg-tertiary text-text-muted px-1.5 py-0.5 rounded font-mono border border-border-default">{t}</span>
                    ))}
                    {(scan.tools || []).length > 3 && (
                      <span className="text-xs text-text-muted font-mono">+{scan.tools.length - 3}</span>
                    )}
                  </div>
                  {scan.status === 'running' && (
                    <div className="mt-2 h-1 bg-bg-tertiary rounded-full overflow-hidden">
                      <div
                        className="h-full bg-accent-primary transition-all duration-1000"
                        style={{ width: `${scan.progress}%` }}
                      />
                    </div>
                  )}
                  <p className="text-text-muted text-xs font-mono mt-1">
                    {new Date(scan.created_at).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Terminal panel */}
        <div className="flex-1 card overflow-hidden flex flex-col min-h-0">
          {selectedScan ? (
            <>
              <div className="flex items-center justify-between p-3 border-b border-border-default flex-shrink-0">
                <div className="flex items-center gap-2">
                  <Terminal size={14} className="text-accent-primary" />
                  <span className="font-mono text-sm text-text-primary">{selectedScan.target_value}</span>
                  <span className="text-xs text-text-muted font-mono">
                    [{(selectedScan.tools || []).join(', ')}]
                  </span>
                </div>
                <button onClick={() => setSelectedScan(null)} className="text-text-muted hover:text-text-primary">
                  <X size={14} />
                </button>
              </div>
              <div className="flex-1 min-h-0">
                <LiveTerminal scanId={selectedScan.id} initialStatus={selectedScan.status} />
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <Terminal size={40} className="text-text-muted mx-auto mb-3" />
                <p className="text-text-secondary text-sm">Select a scan to view live output</p>
                <p className="text-text-muted text-xs font-mono mt-1">or launch a new scan</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
