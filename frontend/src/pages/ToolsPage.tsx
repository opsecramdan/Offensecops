import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Wrench, CheckCircle, XCircle, AlertCircle, RefreshCw, Plus,
  Power, Trash2, Search, ChevronDown, X, Terminal, Package,
  Shield, Globe, Cpu, Zap, Activity, Database
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'

// ── Types ─────────────────────────────────────────────────────
interface Tool {
  id: string
  name: string
  display_name: string
  category: string
  description: string
  version: string
  docker_image: string
  docker_cmd: string
  is_enabled: boolean
  health_status: 'healthy' | 'degraded' | 'offline' | 'unknown'
  health_fail_count: number
  last_health_check: string | null
  allowed_roles: string[]
  resource_limits: { cpu: number, memory: string, timeout: number }
}

// ── Constants ─────────────────────────────────────────────────
const CAT_META: Record<string, { label: string, color: string, icon: any }> = {
  recon:   { label: 'Recon',   color: '#06b6d4', icon: Search },
  web:     { label: 'Web',     color: '#6366f1', icon: Globe },
  network: { label: 'Network', color: '#8b5cf6', icon: Cpu },
  exploit: { label: 'Exploit', color: '#ef4444', icon: Zap },
  utility: { label: 'Utility', color: '#f97316', icon: Wrench },
}

const HEALTH_META = {
  healthy: { icon: CheckCircle, color: 'text-severity-low',      label: 'Healthy'  },
  degraded:{ icon: AlertCircle, color: 'text-severity-medium',   label: 'Degraded' },
  offline: { icon: XCircle,     color: 'text-severity-critical', label: 'Offline'  },
  unknown: { icon: Activity,    color: 'text-text-muted',        label: 'Unknown'  },
}

const DEFAULT_TOOLS = [
  { name: 'amass',     display_name: 'Amass',      category: 'recon',   docker_image: 'caffix/amass:latest',                          version: '4.2.0', description: 'In-depth attack surface mapping and asset discovery' },
  { name: 'subfinder', display_name: 'Subfinder',  category: 'recon',   docker_image: 'projectdiscovery/subfinder:latest',             version: '2.6.6', description: 'Fast passive subdomain enumeration tool' },
  { name: 'httpx',     display_name: 'HTTPX',      category: 'recon',   docker_image: 'projectdiscovery/httpx:latest',                 version: '1.6.7', description: 'Fast and multi-purpose HTTP toolkit' },
  { name: 'dnsx',      display_name: 'DNSx',       category: 'recon',   docker_image: 'projectdiscovery/dnsx:latest',                  version: '1.2.0', description: 'Fast and multi-purpose DNS toolkit' },
  { name: 'nuclei',    display_name: 'Nuclei',     category: 'web',     docker_image: 'projectdiscovery/nuclei:latest',                version: '3.2.0', description: 'Fast and customizable vulnerability scanner' },
  { name: 'dalfox',    display_name: 'DalFox',     category: 'web',     docker_image: 'hahwul/dalfox:latest',                          version: '2.9.2', description: 'Fast parameter analysis and XSS scanner' },
  { name: 'ffuf',      display_name: 'FFUF',       category: 'web',     docker_image: 'ffuf/ffuf:latest',                              version: '2.1.0', description: 'Fast web fuzzer written in Go' },
  { name: 'dirsearch', display_name: 'Dirsearch',  category: 'web',     docker_image: 'dirsearch/dirsearch:latest',                    version: '0.4.3', description: 'Web path discovery tool' },
  { name: 'sqlmap',    display_name: 'SQLMap',     category: 'web',     docker_image: 'paoloo/sqlmap:latest',                          version: '1.8.2', description: 'Automatic SQL injection and database takeover tool' },
  { name: 'ghauri',    display_name: 'Ghauri',     category: 'web',     docker_image: 'r0oth3x49/ghauri:latest',                       version: '1.2.0', description: 'Advanced SQL injection detection and exploitation tool' },
  { name: 'nmap',      display_name: 'Nmap',       category: 'network', docker_image: 'instrumentisto/nmap:latest',                    version: '7.94',  description: 'Network exploration tool and security scanner' },
  { name: 'masscan',   display_name: 'Masscan',    category: 'network', docker_image: 'ivre/masscan:latest',                           version: '1.3.2', description: 'TCP port scanner — fastest in the world' },
]

// ── Register Tool Modal ───────────────────────────────────────
function RegisterToolModal({ onClose, onSuccess }: { onClose: () => void, onSuccess: () => void }) {
  const [form, setForm] = useState({
    name: '', display_name: '', category: 'utility',
    docker_image: '', version: '', description: '',
    docker_cmd: '', binary_path: '',
    resource_limits: { cpu: 1.0, memory: '512m', timeout: 300 },
  })
  const [loading, setLoading] = useState(false)
  const set = (k: string, v: any) => setForm(f => ({ ...f, [k]: v }))

  const handleSubmit = async () => {
    if (!form.name.trim() || !form.docker_image.trim()) {
      toast.error('Name and Docker Image are required')
      return
    }
    setLoading(true)
    try {
      await api.post('/tools/', form)
      toast.success(`Tool "${form.display_name || form.name}" registered`)
      onSuccess(); onClose()
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Failed to register tool')
    } finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-default rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-5 border-b border-border-default sticky top-0 bg-bg-secondary">
          <h2 className="font-display font-bold text-text-primary flex items-center gap-2">
            <Package size={16} className="text-accent-primary" /> Register New Tool
          </h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary"><X size={18} /></button>
        </div>
        <div className="p-5 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label-field">Name * <span className="text-text-muted font-normal">(slug)</span></label>
              <input value={form.name} onChange={e => set('name', e.target.value.toLowerCase().replace(/\s/g, '-'))}
                className="input-field font-mono" placeholder="my-tool" />
            </div>
            <div>
              <label className="label-field">Display Name</label>
              <input value={form.display_name} onChange={e => set('display_name', e.target.value)}
                className="input-field" placeholder="My Tool" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label-field">Category</label>
              <select value={form.category} onChange={e => set('category', e.target.value)} className="input-field">
                {Object.entries(CAT_META).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="label-field">Version</label>
              <input value={form.version} onChange={e => set('version', e.target.value)}
                className="input-field font-mono" placeholder="1.0.0" />
            </div>
          </div>
          <div>
            <label className="label-field">Docker Image *</label>
            <input value={form.docker_image} onChange={e => set('docker_image', e.target.value)}
              className="input-field font-mono" placeholder="projectdiscovery/nuclei:latest" />
          </div>
          <div>
            <label className="label-field">Docker Command <span className="text-text-muted font-normal">(optional)</span></label>
            <input value={form.docker_cmd} onChange={e => set('docker_cmd', e.target.value)}
              className="input-field font-mono text-sm" placeholder="nuclei -u {target} -t {templates}" />
          </div>
          <div>
            <label className="label-field">Description</label>
            <textarea value={form.description} onChange={e => set('description', e.target.value)}
              className="input-field h-20 resize-none text-sm" placeholder="What does this tool do?" />
          </div>
          <div>
            <label className="label-field mb-2">Resource Limits</label>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">CPU cores</label>
                <input type="number" value={form.resource_limits.cpu} step="0.5" min="0.5" max="4"
                  onChange={e => set('resource_limits', { ...form.resource_limits, cpu: parseFloat(e.target.value) })}
                  className="input-field font-mono text-sm" />
              </div>
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">Memory</label>
                <input value={form.resource_limits.memory}
                  onChange={e => set('resource_limits', { ...form.resource_limits, memory: e.target.value })}
                  className="input-field font-mono text-sm" placeholder="512m" />
              </div>
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">Timeout (s)</label>
                <input type="number" value={form.resource_limits.timeout} min="30" max="3600"
                  onChange={e => set('resource_limits', { ...form.resource_limits, timeout: parseInt(e.target.value) })}
                  className="input-field font-mono text-sm" />
              </div>
            </div>
          </div>
        </div>
        <div className="flex gap-3 p-5 border-t border-border-default">
          <button onClick={onClose} className="btn-secondary flex-1">Cancel</button>
          <button onClick={handleSubmit} disabled={loading} className="btn-primary flex-1">
            {loading ? 'Registering...' : 'Register Tool'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Tool Detail Panel ─────────────────────────────────────────
function ToolDetailPanel({ tool, onClose, onRefresh }: { tool: Tool, onClose: () => void, onRefresh: () => void }) {
  const [checkingHealth, setCheckingHealth] = useState(false)
  const queryClient = useQueryClient()

  const toggleMutation = useMutation({
    mutationFn: () => api.patch(`/tools/${tool.id}/toggle`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools'] })
      toast.success(tool.is_enabled ? 'Tool disabled' : 'Tool enabled')
      onRefresh()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/tools/${tool.id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools'] })
      toast.success('Tool removed from registry')
      onClose()
    },
  })

  const handleHealthCheck = async () => {
    setCheckingHealth(true)
    try {
      await api.post(`/tools/${tool.id}/health-check`)
      toast.success('Health check complete')
      queryClient.invalidateQueries({ queryKey: ['tools'] })
      onRefresh()
    } catch { toast.error('Health check failed') }
    finally { setCheckingHealth(false) }
  }

  const hm = HEALTH_META[tool.health_status] || HEALTH_META.unknown
  const cm = CAT_META[tool.category] || CAT_META.utility

  return (
    <div className="card p-5 space-y-4 border-l-2" style={{ borderLeftColor: cm.color }}>
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h3 className="font-display font-bold text-text-primary text-lg">{tool.display_name}</h3>
            <span className="text-xs font-mono px-2 py-0.5 rounded border"
              style={{ borderColor: cm.color, color: cm.color, backgroundColor: cm.color + '15' }}>
              {cm.label}
            </span>
          </div>
          <p className="text-sm text-text-secondary">{tool.description}</p>
        </div>
        <button onClick={onClose} className="text-text-muted hover:text-text-primary ml-4 flex-shrink-0">
          <X size={16} />
        </button>
      </div>

      {/* Status row */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-bg-tertiary rounded-lg p-3 border border-border-default">
          <p className="text-xs font-mono text-text-muted mb-1">Status</p>
          <div className={`flex items-center gap-1.5 ${hm.color}`}>
            <hm.icon size={14} />
            <span className="text-sm font-mono font-bold">{hm.label}</span>
          </div>
        </div>
        <div className="bg-bg-tertiary rounded-lg p-3 border border-border-default">
          <p className="text-xs font-mono text-text-muted mb-1">Version</p>
          <p className="text-sm font-mono text-text-primary">{tool.version || '—'}</p>
        </div>
        <div className="bg-bg-tertiary rounded-lg p-3 border border-border-default">
          <p className="text-xs font-mono text-text-muted mb-1">Enabled</p>
          <p className={`text-sm font-mono font-bold ${tool.is_enabled ? 'text-severity-low' : 'text-text-muted'}`}>
            {tool.is_enabled ? 'Yes' : 'No'}
          </p>
        </div>
      </div>

      {/* Docker info */}
      <div className="space-y-2">
        <div className="flex items-start gap-2 p-3 bg-bg-tertiary rounded-lg border border-border-default">
          <Database size={13} className="text-text-muted mt-0.5 flex-shrink-0" />
          <div className="min-w-0">
            <p className="text-xs font-mono text-text-muted mb-0.5">Docker Image</p>
            <p className="text-xs font-mono text-accent-primary break-all">{tool.docker_image}</p>
          </div>
        </div>
        {tool.docker_cmd && (
          <div className="flex items-start gap-2 p-3 bg-bg-tertiary rounded-lg border border-border-default">
            <Terminal size={13} className="text-text-muted mt-0.5 flex-shrink-0" />
            <div className="min-w-0">
              <p className="text-xs font-mono text-text-muted mb-0.5">Command Template</p>
              <p className="text-xs font-mono text-text-secondary break-all">{tool.docker_cmd}</p>
            </div>
          </div>
        )}
      </div>

      {/* Resource limits */}
      <div>
        <p className="text-xs font-mono text-text-muted mb-2">Resource Limits</p>
        <div className="flex gap-3">
          {[
            ['CPU', `${tool.resource_limits?.cpu || 1} core(s)`],
            ['Memory', tool.resource_limits?.memory || '512m'],
            ['Timeout', `${tool.resource_limits?.timeout || 300}s`],
          ].map(([k, v]) => (
            <div key={k} className="flex-1 bg-bg-tertiary rounded-lg p-2.5 border border-border-default text-center">
              <p className="text-xs font-mono text-text-muted">{k}</p>
              <p className="text-xs font-mono text-text-primary font-bold mt-0.5">{v}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Last health check */}
      {tool.last_health_check && (
        <p className="text-xs font-mono text-text-muted">
          Last checked: {new Date(tool.last_health_check).toLocaleString()}
          {tool.health_fail_count > 0 && <span className="text-severity-critical ml-2">({tool.health_fail_count} fail(s))</span>}
        </p>
      )}

      {/* Actions */}
      <div className="grid grid-cols-3 gap-2 pt-2 border-t border-border-default">
        <button onClick={handleHealthCheck} disabled={checkingHealth}
          className="flex items-center justify-center gap-1.5 py-2 text-xs font-mono rounded-lg border border-border-default text-text-secondary hover:border-accent-primary hover:text-accent-primary transition-all disabled:opacity-50">
          {checkingHealth
            ? <><RefreshCw size={11} className="animate-spin" />Checking...</>
            : <><Activity size={11} />Health Check</>
          }
        </button>
        <button onClick={() => toggleMutation.mutate()}
          className={`flex items-center justify-center gap-1.5 py-2 text-xs font-mono rounded-lg border transition-all ${
            tool.is_enabled
              ? 'border-severity-medium text-severity-medium hover:bg-severity-medium hover:bg-opacity-10'
              : 'border-severity-low text-severity-low hover:bg-severity-low hover:bg-opacity-10'
          }`}>
          <Power size={11} /> {tool.is_enabled ? 'Disable' : 'Enable'}
        </button>
        <button onClick={() => {
            if (confirm(`Remove "${tool.display_name}" from registry?`)) deleteMutation.mutate()
          }}
          className="flex items-center justify-center gap-1.5 py-2 text-xs font-mono rounded-lg border border-severity-critical text-severity-critical hover:bg-severity-critical hover:bg-opacity-10 transition-all">
          <Trash2 size={11} /> Remove
        </button>
      </div>
    </div>
  )
}

// ── Tool Card ─────────────────────────────────────────────────
function ToolCard({ tool, selected, onClick }: { tool: Tool, selected: boolean, onClick: () => void }) {
  const hm = HEALTH_META[tool.health_status] || HEALTH_META.unknown
  const cm = CAT_META[tool.category] || CAT_META.utility

  return (
    <button onClick={onClick}
      className={`w-full text-left p-4 rounded-xl border transition-all ${
        selected
          ? 'border-accent-primary bg-accent-primary bg-opacity-5'
          : 'card hover:border-border-muted'
      } ${!tool.is_enabled ? 'opacity-50' : ''}`}>
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="font-mono font-bold text-text-primary text-sm">{tool.display_name}</span>
          {!tool.is_enabled && (
            <span className="text-xs font-mono text-text-muted border border-border-default px-1.5 py-0.5 rounded">OFF</span>
          )}
        </div>
        <hm.icon size={14} className={hm.color} />
      </div>
      <p className="text-xs text-text-muted line-clamp-2 mb-3">{tool.description}</p>
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono px-2 py-0.5 rounded border"
          style={{ borderColor: cm.color + '60', color: cm.color, backgroundColor: cm.color + '10' }}>
          {cm.label}
        </span>
        <span className="text-xs font-mono text-text-muted">v{tool.version}</span>
      </div>
    </button>
  )
}

// ── Seed Button ───────────────────────────────────────────────
function SeedButton({ onSuccess }: { onSuccess: () => void }) {
  const [loading, setLoading] = useState(false)

  const handleSeed = async () => {
    setLoading(true)
    try {
      const res = await api.post('/tools/seed')
      const d = res.data
      toast.success(`Seeded ${d.added} tool(s)${d.skipped > 0 ? `, ${d.skipped} already existed` : ''}`)
      onSuccess()
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Seed failed')
    } finally { setLoading(false) }
  }

  return (
    <button onClick={handleSeed} disabled={loading}
      className="btn-secondary flex items-center gap-2 text-sm">
      {loading ? <RefreshCw size={14} className="animate-spin" /> : <Database size={14} />}
      {loading ? 'Seeding...' : 'Seed Defaults'}
    </button>
  )
}

// ── Health Check All ──────────────────────────────────────────
function HealthCheckAllButton({ tools, onDone }: { tools: Tool[], onDone: () => void }) {
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)

  const handleCheckAll = async () => {
    if (tools.length === 0) return
    setLoading(true)
    setProgress(0)
    let done = 0
    for (const tool of tools) {
      try {
        await api.post(`/tools/${tool.id}/health-check`)
      } catch {}
      done++
      setProgress(Math.round((done / tools.length) * 100))
    }
    setLoading(false)
    setProgress(0)
    toast.success(`Health check complete — ${tools.length} tools checked`)
    onDone()
  }

  return (
    <button onClick={handleCheckAll} disabled={loading}
      className="btn-secondary flex items-center gap-2 text-sm">
      <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
      {loading ? `Checking... ${progress}%` : 'Health Check All'}
    </button>
  )
}

// ── Main Page ─────────────────────────────────────────────────
export default function ToolsPage() {
  const [search, setSearch] = useState('')
  const [filterCat, setFilterCat] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null)
  const [showRegister, setShowRegister] = useState(false)
  const queryClient = useQueryClient()

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['tools'],
    queryFn: () => api.get('/tools/').then(r => r.data),
    staleTime: 30000,
  })

  const tools: Tool[] = data?.items || []

  const filtered = tools.filter(t => {
    if (search && !t.name.includes(search.toLowerCase()) && !t.display_name.toLowerCase().includes(search.toLowerCase())) return false
    if (filterCat && t.category !== filterCat) return false
    if (filterStatus && t.health_status !== filterStatus) return false
    return true
  })

  // Stats
  const healthy = tools.filter(t => t.health_status === 'healthy').length
  const enabled  = tools.filter(t => t.is_enabled).length
  const cats = [...new Set(tools.map(t => t.category))]

  const onSuccess = () => {
    queryClient.invalidateQueries({ queryKey: ['tools'] })
    setSelectedTool(null)
  }

  // Update selectedTool when data refreshes
  const refreshSelected = () => {
    if (selectedTool) {
      refetch().then(res => {
        const updated = (res.data?.items || []).find((t: Tool) => t.id === selectedTool.id)
        if (updated) setSelectedTool(updated)
      })
    } else {
      refetch()
    }
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {showRegister && (
        <RegisterToolModal onClose={() => setShowRegister(false)} onSuccess={onSuccess} />
      )}

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
            <Wrench size={24} className="text-accent-primary" /> Tool Registry
          </h1>
          <p className="text-text-muted text-sm font-mono mt-1">
            {isLoading ? '...' : `${healthy}/${tools.length} healthy · ${enabled} enabled`}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <HealthCheckAllButton tools={tools} onDone={refreshSelected} />
          {tools.length === 0 && !isLoading && (
            <SeedButton onSuccess={onSuccess} />
          )}
          <button onClick={() => setShowRegister(true)} className="btn-primary flex items-center gap-2 text-sm">
            <Plus size={14} /> Register Tool
          </button>
        </div>
      </div>

      {/* Stats */}
      {!isLoading && tools.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Total Tools',  value: tools.length,  color: '#6366f1', icon: Package },
            { label: 'Healthy',      value: healthy,        color: '#22c55e', icon: CheckCircle },
            { label: 'Enabled',      value: enabled,        color: '#06b6d4', icon: Power },
            { label: 'Categories',   value: cats.length,    color: '#f97316', icon: Shield },
          ].map(({ label, value, color, icon: Icon }) => (
            <div key={label} className="card p-4 flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                style={{ backgroundColor: color + '20' }}>
                <Icon size={16} style={{ color }} />
              </div>
              <div>
                <p className="text-xl font-display font-bold text-text-primary">{value}</p>
                <p className="text-xs font-mono text-text-muted">{label}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="card p-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search tools..." className="input-field pl-9" />
        </div>
        <select value={filterCat} onChange={e => setFilterCat(e.target.value)} className="input-field w-36">
          <option value="">All categories</option>
          {Object.entries(CAT_META).map(([k, v]) => (
            <option key={k} value={k}>{v.label}</option>
          ))}
        </select>
        <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} className="input-field w-36">
          <option value="">All status</option>
          <option value="healthy">Healthy</option>
          <option value="degraded">Degraded</option>
          <option value="offline">Offline</option>
          <option value="unknown">Unknown</option>
        </select>
      </div>

      {/* Empty state */}
      {!isLoading && tools.length === 0 && (
        <div className="card p-16 text-center">
          <Wrench size={48} className="text-text-muted mx-auto mb-4" />
          <p className="text-text-secondary font-mono mb-2">No tools registered yet.</p>
          <p className="text-text-muted text-sm mb-6">Seed the default tools to get started.</p>
          <SeedButton onSuccess={onSuccess} />
        </div>
      )}

      {/* Loading */}
      {isLoading && (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-accent-primary border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {/* Grid + Detail */}
      {!isLoading && tools.length > 0 && (
        <div className={`grid gap-4 ${selectedTool ? 'grid-cols-1 lg:grid-cols-3' : 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'}`}>
          {/* Tool cards */}
          <div className={`${selectedTool ? 'lg:col-span-2' : ''}`}>
            {filtered.length === 0 ? (
              <div className="card p-10 text-center text-text-muted text-sm font-mono">No tools match filter</div>
            ) : (
              <div className={`grid gap-3 ${selectedTool ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1'}`}>
                {filtered.map(tool => (
                  <ToolCard key={tool.id} tool={tool}
                    selected={selectedTool?.id === tool.id}
                    onClick={() => setSelectedTool(prev => prev?.id === tool.id ? null : tool)}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Detail panel */}
          {selectedTool && (
            <div className="lg:col-span-1">
              <ToolDetailPanel
                tool={selectedTool}
                onClose={() => setSelectedTool(null)}
                onRefresh={refreshSelected}
              />
            </div>
          )}
        </div>
      )}

      {/* Category breakdown */}
      {!isLoading && tools.length > 0 && (
        <div className="card p-5">
          <p className="text-xs font-mono text-text-muted uppercase tracking-wider mb-4">By Category</p>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
            {Object.entries(CAT_META).map(([cat, meta]) => {
              const count = tools.filter(t => t.category === cat).length
              const healthyCount = tools.filter(t => t.category === cat && t.health_status === 'healthy').length
              const Icon = meta.icon
              return (
                <button key={cat} onClick={() => setFilterCat(filterCat === cat ? '' : cat)}
                  className={`p-3 rounded-lg border transition-all text-left ${
                    filterCat === cat ? 'border-opacity-80' : 'border-border-default hover:border-border-muted'
                  }`}
                  style={filterCat === cat ? { borderColor: meta.color, backgroundColor: meta.color + '10' } : {}}>
                  <div className="flex items-center gap-2 mb-2">
                    <Icon size={14} style={{ color: meta.color }} />
                    <span className="text-xs font-mono font-bold text-text-primary">{meta.label}</span>
                  </div>
                  <p className="text-xl font-display font-bold" style={{ color: meta.color }}>{count}</p>
                  <p className="text-xs font-mono text-text-muted">{healthyCount} healthy</p>
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
