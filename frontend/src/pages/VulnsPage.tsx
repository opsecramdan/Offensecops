import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Search, Download, Filter, X, AlertTriangle, CheckCircle, Clock, ChevronDown, ChevronRight, Trash2, Edit } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'

// ── Constants ────────────────────────────────────────────────
const SEV_COLORS: Record<string, string> = {
  critical: 'badge-critical', high: 'badge-high',
  medium: 'badge-medium', low: 'badge-low', informational: 'badge-info',
}
const SEV_BG: Record<string, string> = {
  critical: 'bg-severity-critical', high: 'bg-severity-high',
  medium: 'bg-severity-medium', low: 'bg-severity-low', informational: 'bg-accent-secondary',
}
const STATUS_COLOR: Record<string, string> = {
  open: 'text-severity-critical', in_remediation: 'text-severity-medium',
  false_positive: 'text-text-muted', resolved: 'text-severity-low',
}
const SLA_DAYS: Record<string, number> = {
  critical: 7, high: 30, medium: 90, low: 180, informational: 365,
}

// ── CVSS Calculator ──────────────────────────────────────────
function cvssFromVector(vector: string): number | null {
  // Simplified CVSS v3 estimator from AV/AC/PR/UI/S/C/I/A
  if (!vector) return null
  try {
    const parts: Record<string, string> = {}
    vector.split('/').forEach(p => {
      const [k, v] = p.split(':')
      if (k && v) parts[k] = v
    })
    // Very rough estimate
    const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[parts['AV']] ?? 0.85
    const ac = { L: 0.77, H: 0.44 }[parts['AC']] ?? 0.77
    const pr = { N: 0.85, L: 0.62, H: 0.27 }[parts['PR']] ?? 0.85
    const ui = { N: 0.85, R: 0.62 }[parts['UI']] ?? 0.85
    const impact = [parts['C'], parts['I'], parts['A']].reduce((acc, v) => {
      return acc + ({ N: 0, L: 0.22, H: 0.56 }[v ?? 'N'] ?? 0)
    }, 0)
    const iss = 1 - (1 - (impact / 3)) * (1 - (impact / 3)) * (1 - (impact / 3))
    const score = Math.min(10, (av * ac * pr * ui) * iss * 10)
    return Math.round(score * 10) / 10
  } catch {
    return null
  }
}

function cvssColor(score: number | null): string {
  if (!score) return 'text-text-muted'
  if (score >= 9.0) return 'text-severity-critical'
  if (score >= 7.0) return 'text-severity-high'
  if (score >= 4.0) return 'text-severity-medium'
  return 'text-severity-low'
}

// ── SLA Badge ────────────────────────────────────────────────
function SlaBadge({ daysLeft, status }: { daysLeft: number | null, status: string }) {
  if (status === 'resolved' || daysLeft === null) return null
  if (daysLeft < 0) return (
    <span className="inline-flex items-center gap-1 text-xs font-mono text-severity-critical bg-severity-critical bg-opacity-10 border border-severity-critical border-opacity-30 px-2 py-0.5 rounded">
      <AlertTriangle size={10} /> SLA Breached {Math.abs(daysLeft)}d ago
    </span>
  )
  if (daysLeft <= 7) return (
    <span className="inline-flex items-center gap-1 text-xs font-mono text-severity-high bg-severity-high bg-opacity-10 border border-severity-high border-opacity-30 px-2 py-0.5 rounded">
      <Clock size={10} /> {daysLeft}d left
    </span>
  )
  return (
    <span className="text-xs font-mono text-text-muted">{daysLeft}d left</span>
  )
}

// ── Add Vuln Modal ───────────────────────────────────────────
function AddVulnModal({ onClose, onSuccess }: { onClose: () => void, onSuccess: () => void }) {
  const [form, setForm] = useState({
    title: '', description: '', severity: 'medium',
    cvss_score: '', cvss_vector: '', affected_asset: '',
    cve_ids: '', cwe_ids: '', remediation_notes: '',
    references: '', status: 'open',
  })
  const [loading, setLoading] = useState(false)
  const set = (k: string, v: string) => setForm(f => ({ ...f, [k]: v }))

  // Auto-calc CVSS from vector
  const calcScore = () => {
    const score = cvssFromVector(form.cvss_vector)
    if (score) set('cvss_score', String(score))
  }

  // Auto-set severity from CVSS score
  const scoreToSeverity = (score: string) => {
    const n = parseFloat(score)
    if (isNaN(n)) return
    if (n >= 9.0) set('severity', 'critical')
    else if (n >= 7.0) set('severity', 'high')
    else if (n >= 4.0) set('severity', 'medium')
    else if (n > 0) set('severity', 'low')
  }

  const handleSubmit = async () => {
    if (!form.title.trim()) { toast.error('Title harus diisi'); return }
    setLoading(true)
    try {
      await api.post('/vulns/', {
        title: form.title,
        description: form.description || null,
        severity: form.severity,
        cvss_score: parseFloat(form.cvss_score) || null,
        cvss_vector: form.cvss_vector || null,
        affected_asset: form.affected_asset || null,
        cve_ids: form.cve_ids ? form.cve_ids.split(',').map(s => s.trim()).filter(Boolean) : [],
        cwe_ids: form.cwe_ids ? form.cwe_ids.split(',').map(s => s.trim()).filter(Boolean) : [],
        remediation_notes: form.remediation_notes || null,
        references: form.references ? form.references.split('\n').map(s => s.trim()).filter(Boolean) : [],
      })
      toast.success('Vulnerability added')
      onSuccess()
      onClose()
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Failed to add vulnerability')
    } finally { setLoading(false) }
  }

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']
  const slaPreview = SLA_DAYS[form.severity]

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-default rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-5 border-b border-border-default sticky top-0 bg-bg-secondary">
          <h2 className="font-display font-bold text-text-primary flex items-center gap-2">
            <Shield size={18} className="text-accent-primary" /> Add Vulnerability
          </h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary"><X size={18} /></button>
        </div>

        <div className="p-5 space-y-4">
          {/* Title */}
          <div>
            <label className="label-field">Title *</label>
            <input value={form.title} onChange={e => set('title', e.target.value)}
              className="input-field" placeholder="SQL Injection in /api/users endpoint" />
          </div>

          {/* Severity + CVSS */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label-field">Severity</label>
              <div className="flex gap-2 flex-wrap mt-1">
                {SEVERITIES.map(s => (
                  <button key={s} onClick={() => set('severity', s)}
                    className={`text-xs font-mono px-3 py-1.5 rounded border transition-all capitalize ${
                      form.severity === s
                        ? `${SEV_BG[s]} bg-opacity-20 border-current text-white`
                        : 'border-border-default text-text-muted hover:border-border-muted'
                    }`}>{s}</button>
                ))}
              </div>
              <p className="text-text-muted text-xs font-mono mt-1.5">
                SLA: {slaPreview} days from discovery
              </p>
            </div>
            <div className="space-y-2">
              <div>
                <label className="label-field">CVSS Score (0–10)</label>
                <input value={form.cvss_score}
                  onChange={e => { set('cvss_score', e.target.value); scoreToSeverity(e.target.value) }}
                  type="number" min="0" max="10" step="0.1"
                  className="input-field" placeholder="7.5" />
              </div>
              <div>
                <label className="label-field">CVSS Vector</label>
                <div className="flex gap-2">
                  <input value={form.cvss_vector} onChange={e => set('cvss_vector', e.target.value)}
                    className="input-field flex-1 font-mono text-xs" placeholder="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" />
                  <button onClick={calcScore} className="btn-secondary text-xs px-2 whitespace-nowrap">Calc</button>
                </div>
              </div>
            </div>
          </div>

          {/* Asset */}
          <div>
            <label className="label-field">Affected Asset</label>
            <input value={form.affected_asset} onChange={e => set('affected_asset', e.target.value)}
              className="input-field font-mono" placeholder="https://api.target.com/users?id=1" />
          </div>

          {/* CVE / CWE */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label-field">CVE IDs (comma separated)</label>
              <input value={form.cve_ids} onChange={e => set('cve_ids', e.target.value)}
                className="input-field font-mono text-sm" placeholder="CVE-2021-44228, CVE-2023-1234" />
            </div>
            <div>
              <label className="label-field">CWE IDs (comma separated)</label>
              <input value={form.cwe_ids} onChange={e => set('cwe_ids', e.target.value)}
                className="input-field font-mono text-sm" placeholder="CWE-89, CWE-79" />
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="label-field">Description</label>
            <textarea value={form.description} onChange={e => set('description', e.target.value)}
              className="input-field h-24 resize-none"
              placeholder="Describe the vulnerability, how it was found, and its impact..." />
          </div>

          {/* Remediation */}
          <div>
            <label className="label-field">Remediation Notes</label>
            <textarea value={form.remediation_notes} onChange={e => set('remediation_notes', e.target.value)}
              className="input-field h-20 resize-none"
              placeholder="Steps to remediate this vulnerability..." />
          </div>

          {/* References */}
          <div>
            <label className="label-field">References (one URL per line)</label>
            <textarea value={form.references} onChange={e => set('references', e.target.value)}
              className="input-field h-16 resize-none font-mono text-xs"
              placeholder="https://nvd.nist.gov/vuln/detail/CVE-2021-44228" />
          </div>
        </div>

        <div className="flex gap-3 p-5 border-t border-border-default">
          <button onClick={onClose} className="btn-secondary flex-1">Cancel</button>
          <button onClick={handleSubmit} disabled={loading} className="btn-primary flex-1">
            {loading ? 'Adding...' : 'Add Vulnerability'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Vuln Detail Drawer ───────────────────────────────────────
function VulnDetail({ vuln, onClose, onUpdate }: { vuln: any, onClose: () => void, onUpdate: () => void }) {
  const [editing, setEditing] = useState(false)
  const [status, setStatus] = useState(vuln.status)
  const [notes, setNotes] = useState(vuln.remediation_notes || '')
  const [loading, setLoading] = useState(false)
  const queryClient = useQueryClient()

  const handleSave = async () => {
    setLoading(true)
    try {
      await api.patch(`/vulns/${vuln.id}`, { status, remediation_notes: notes })
      toast.success('Updated')
      queryClient.invalidateQueries({ queryKey: ['vulns'] })
      onUpdate()
      setEditing(false)
    } catch {
      toast.error('Update failed')
    } finally { setLoading(false) }
  }

  const markFP = async () => {
    const reason = prompt('Reason for marking as false positive?')
    if (!reason) return
    try {
      await api.patch(`/vulns/${vuln.id}`, { is_false_positive: true, fp_reason: reason })
      toast.success('Marked as false positive')
      queryClient.invalidateQueries({ queryKey: ['vulns'] })
      onClose()
    } catch { toast.error('Failed') }
  }

  const STATUSES = ['open', 'in_remediation', 'false_positive', 'resolved']

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-bg-secondary border-l border-border-default shadow-2xl z-40 flex flex-col">
      {/* Header */}
      <div className="flex items-start justify-between p-5 border-b border-border-default flex-shrink-0">
        <div className="flex-1 min-w-0 mr-3">
          <div className="flex items-center gap-2 mb-1">
            <span className={SEV_COLORS[vuln.severity]}>{vuln.severity}</span>
            {vuln.cvss_score && (
              <span className={`text-sm font-mono font-bold ${cvssColor(vuln.cvss_score)}`}>
                CVSS {vuln.cvss_score}
              </span>
            )}
          </div>
          <h2 className="font-display font-bold text-text-primary text-lg leading-tight">{vuln.title}</h2>
          {vuln.affected_asset && (
            <p className="font-mono text-xs text-text-muted mt-1 truncate">{vuln.affected_asset}</p>
          )}
        </div>
        <button onClick={onClose} className="text-text-muted hover:text-text-primary flex-shrink-0">
          <X size={18} />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* SLA */}
        <div className="flex items-center gap-3 p-3 bg-bg-tertiary rounded-lg border border-border-default">
          <Clock size={16} className="text-text-muted flex-shrink-0" />
          <div>
            <p className="text-xs text-text-muted font-mono uppercase">SLA Due Date</p>
            <p className="text-sm text-text-primary font-mono">
              {vuln.sla_due_date ? new Date(vuln.sla_due_date).toLocaleDateString() : '—'}
            </p>
          </div>
          <div className="ml-auto">
            <SlaBadge daysLeft={vuln.sla_days_left} status={vuln.status} />
          </div>
        </div>

        {/* Status + Edit */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="label-field">Status</label>
            <button onClick={() => setEditing(!editing)}
              className="text-xs text-accent-primary font-mono hover:underline flex items-center gap-1">
              <Edit size={11} /> {editing ? 'Cancel' : 'Edit'}
            </button>
          </div>
          {editing ? (
            <select value={status} onChange={e => setStatus(e.target.value)} className="input-field">
              {STATUSES.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>
          ) : (
            <span className={`text-sm font-mono font-medium ${STATUS_COLOR[vuln.status]}`}>
              {vuln.status.replace('_', ' ').toUpperCase()}
            </span>
          )}
        </div>

        {/* CVE / CWE */}
        {(vuln.cve_ids?.length > 0 || vuln.cwe_ids?.length > 0) && (
          <div className="flex gap-3 flex-wrap">
            {vuln.cve_ids?.map((cve: string) => (
              <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener"
                className="text-xs font-mono text-accent-primary border border-accent-primary border-opacity-40 px-2 py-0.5 rounded hover:bg-accent-primary hover:bg-opacity-10 transition-colors">
                {cve}
              </a>
            ))}
            {vuln.cwe_ids?.map((cwe: string) => (
              <span key={cwe} className="text-xs font-mono text-text-muted border border-border-default px-2 py-0.5 rounded">{cwe}</span>
            ))}
          </div>
        )}

        {/* MITRE */}
        {vuln.mitre_techniques?.length > 0 && (
          <div>
            <label className="label-field mb-2">MITRE ATT&CK</label>
            <div className="flex flex-wrap gap-2">
              {vuln.mitre_techniques.map((t: string) => (
                <span key={t} className="text-xs font-mono bg-bg-tertiary border border-border-default px-2 py-0.5 rounded text-text-secondary">{t}</span>
              ))}
            </div>
          </div>
        )}

        {/* Description */}
        {vuln.description && (
          <div>
            <label className="label-field mb-2">Description</label>
            <p className="text-sm text-text-secondary leading-relaxed whitespace-pre-wrap">{vuln.description}</p>
          </div>
        )}

        {/* Remediation */}
        <div>
          <label className="label-field mb-2">Remediation Notes</label>
          {editing ? (
            <textarea value={notes} onChange={e => setNotes(e.target.value)}
              className="input-field h-28 resize-none text-sm" placeholder="Add remediation steps..." />
          ) : vuln.remediation_notes ? (
            <p className="text-sm text-text-secondary leading-relaxed whitespace-pre-wrap bg-bg-tertiary p-3 rounded-lg border border-border-default">
              {vuln.remediation_notes}
            </p>
          ) : (
            <p className="text-sm text-text-muted italic">No remediation notes yet</p>
          )}
        </div>

        {/* Evidence */}
        {vuln.evidence && Object.keys(vuln.evidence).length > 0 && (
          <div>
            <label className="label-field mb-2">Evidence</label>
            <pre className="text-xs font-mono bg-black text-green-400 p-3 rounded-lg overflow-x-auto">
              {JSON.stringify(vuln.evidence, null, 2)}
            </pre>
          </div>
        )}

        {/* References */}
        {vuln.references?.length > 0 && (
          <div>
            <label className="label-field mb-2">References</label>
            <div className="space-y-1">
              {vuln.references.map((ref: string, i: number) => (
                <a key={i} href={ref} target="_blank" rel="noopener"
                  className="block text-xs font-mono text-accent-primary hover:underline truncate">{ref}</a>
              ))}
            </div>
          </div>
        )}

        {/* Timestamps */}
        <div className="text-xs font-mono text-text-muted space-y-1 pt-2 border-t border-border-default">
          <p>Created: {vuln.created_at ? new Date(vuln.created_at).toLocaleString() : '—'}</p>
          {vuln.resolved_at && <p>Resolved: {new Date(vuln.resolved_at).toLocaleString()}</p>}
        </div>
      </div>

      {/* Actions */}
      <div className="p-4 border-t border-border-default flex-shrink-0 flex gap-2">
        {editing ? (
          <>
            <button onClick={() => setEditing(false)} className="btn-secondary flex-1">Cancel</button>
            <button onClick={handleSave} disabled={loading} className="btn-primary flex-1">
              {loading ? 'Saving...' : 'Save Changes'}
            </button>
          </>
        ) : (
          <>
            <button onClick={markFP} className="btn-secondary text-sm flex-1">Mark False Positive</button>
            <button onClick={() => { setStatus('resolved'); setEditing(true) }}
              className="btn-primary text-sm flex-1 flex items-center justify-center gap-1">
              <CheckCircle size={13} /> Mark Resolved
            </button>
          </>
        )}
      </div>
    </div>
  )
}

// ── Stats Bar ────────────────────────────────────────────────
function StatsBar({ stats }: { stats: any }) {
  if (!stats) return null
  const sevs = ['critical', 'high', 'medium', 'low', 'informational']
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
      {sevs.map(s => (
        <div key={s} className="card p-3">
          <p className="text-text-muted text-xs font-mono uppercase mb-1">{s}</p>
          <p className={`text-2xl font-display font-bold ${
            s === 'critical' ? 'text-severity-critical' :
            s === 'high' ? 'text-severity-high' :
            s === 'medium' ? 'text-severity-medium' :
            s === 'low' ? 'text-severity-low' : 'text-text-secondary'
          }`}>{stats.by_severity?.[s] ?? 0}</p>
        </div>
      ))}
      <div className="card p-3 border-severity-critical border-opacity-40">
        <p className="text-text-muted text-xs font-mono uppercase mb-1">SLA Breached</p>
        <p className="text-2xl font-display font-bold text-severity-critical">{stats.sla_breached ?? 0}</p>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────
export default function VulnsPage() {
  const [search, setSearch] = useState('')
  const [filterSev, setFilterSev] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterSLA, setFilterSLA] = useState(false)
  const [sortBy, setSortBy] = useState('created_at')
  const [showAdd, setShowAdd] = useState(false)
  const [selectedVuln, setSelectedVuln] = useState<any>(null)
  const queryClient = useQueryClient()

  const statsQuery = useQuery({
    queryKey: ['vuln-stats'],
    queryFn: () => api.get('/vulns/stats').then(r => r.data),
  })

  const { data, isLoading } = useQuery({
    queryKey: ['vulns', search, filterSev, filterStatus, filterSLA, sortBy],
    queryFn: () => api.get('/vulns/', {
      params: {
        search: search || undefined,
        severity: filterSev || undefined,
        status: filterStatus || undefined,
        sla_breached: filterSLA || undefined,
        sort_by: sortBy,
        limit: 100,
      }
    }).then(r => r.data),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/vulns/${id}`),
    onSuccess: () => {
      toast.success('Deleted')
      queryClient.invalidateQueries({ queryKey: ['vulns'] })
      queryClient.invalidateQueries({ queryKey: ['vuln-stats'] })
      if (selectedVuln) setSelectedVuln(null)
    },
    onError: () => toast.error('Delete failed'),
  })

  const exportCSV = async () => {
    try {
      const res = await api.get('/vulns/export/csv', { responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = 'vulnerabilities.csv'
      a.click()
      URL.revokeObjectURL(url)
    } catch { toast.error('Export failed') }
  }

  const vulns = data?.items || []

  return (
    <div className="space-y-5 animate-fade-in">
      {showAdd && (
        <AddVulnModal
          onClose={() => setShowAdd(false)}
          onSuccess={() => {
            queryClient.invalidateQueries({ queryKey: ['vulns'] })
            queryClient.invalidateQueries({ queryKey: ['vuln-stats'] })
          }}
        />
      )}

      {selectedVuln && (
        <VulnDetail
          vuln={selectedVuln}
          onClose={() => setSelectedVuln(null)}
          onUpdate={() => {
            queryClient.invalidateQueries({ queryKey: ['vulns'] })
            queryClient.invalidateQueries({ queryKey: ['vuln-stats'] })
          }}
        />
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
            <Shield size={24} className="text-accent-primary" /> Vulnerabilities
          </h1>
          <p className="text-text-muted text-sm font-mono mt-1">
            {isLoading ? '...' : `${data?.total ?? 0} findings`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={exportCSV} className="btn-secondary flex items-center gap-2">
            <Download size={14} /> Export CSV
          </button>
          <button onClick={() => setShowAdd(true)} className="btn-primary flex items-center gap-2">
            <Plus size={14} /> Add Finding
          </button>
        </div>
      </div>

      {/* Stats */}
      <StatsBar stats={statsQuery.data} />

      {/* Filters */}
      <div className="card p-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search title, asset..." className="input-field pl-9" />
        </div>
        <select value={filterSev} onChange={e => setFilterSev(e.target.value)} className="input-field w-36">
          <option value="">All severity</option>
          {['critical','high','medium','low','informational'].map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} className="input-field w-40">
          <option value="">All status</option>
          {['open','in_remediation','false_positive','resolved'].map(s => (
            <option key={s} value={s}>{s.replace('_',' ')}</option>
          ))}
        </select>
        <select value={sortBy} onChange={e => setSortBy(e.target.value)} className="input-field w-36">
          <option value="created_at">Newest</option>
          <option value="cvss_score">CVSS Score</option>
          <option value="sla_due_date">SLA Due</option>
          <option value="severity">Severity</option>
        </select>
        <button
          onClick={() => setFilterSLA(!filterSLA)}
          className={`flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border transition-all ${
            filterSLA
              ? 'bg-severity-critical bg-opacity-10 border-severity-critical text-severity-critical'
              : 'border-border-default text-text-muted hover:border-border-muted'
          }`}
        >
          <AlertTriangle size={12} /> SLA Breached
        </button>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-accent-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : vulns.length === 0 ? (
        <div className="card p-16 text-center">
          <Shield size={40} className="text-text-muted mx-auto mb-3" />
          <p className="text-text-secondary">No vulnerabilities found.</p>
          <button onClick={() => setShowAdd(true)} className="btn-primary mt-4 inline-flex items-center gap-2">
            <Plus size={14} /> Add Finding
          </button>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border-default">
                {['Severity', 'Title', 'Asset', 'CVSS', 'Status', 'SLA', 'Actions'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-text-muted text-xs font-mono uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border-default">
              {vulns.map((v: any) => (
                <tr key={v.id}
                  onClick={() => setSelectedVuln(v)}
                  className="hover:bg-bg-hover transition-colors cursor-pointer group"
                >
                  <td className="px-4 py-3">
                    <span className={SEV_COLORS[v.severity]}>{v.severity}</span>
                  </td>
                  <td className="px-4 py-3 max-w-xs">
                    <p className="text-sm text-text-primary truncate">{v.title}</p>
                    {v.cve_ids?.length > 0 && (
                      <p className="text-xs font-mono text-accent-primary mt-0.5">{v.cve_ids[0]}</p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-mono text-text-secondary truncate max-w-32 block">
                      {v.affected_asset || '—'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {v.cvss_score ? (
                      <span className={`text-sm font-mono font-bold ${cvssColor(v.cvss_score)}`}>
                        {v.cvss_score}
                      </span>
                    ) : <span className="text-text-muted">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-mono ${STATUS_COLOR[v.status]}`}>
                      {v.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <SlaBadge daysLeft={v.sla_days_left} status={v.status} />
                  </td>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    <button
                      onClick={() => { if(confirm('Delete this finding?')) deleteMutation.mutate(v.id) }}
                      className="opacity-0 group-hover:opacity-100 text-severity-critical hover:opacity-70 transition-all"
                    >
                      <Trash2 size={13} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
