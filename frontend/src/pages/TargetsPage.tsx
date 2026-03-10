import { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Target, Plus, Search, RefreshCw, Upload, Grid, List,
  Trash2, Zap, X, Edit, Copy, ChevronDown, Loader,
  Globe, Server, Download, FolderPlus, Folder, Tag
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'

const CRIT_COLOR: Record<string, string> = {
  critical: 'badge-critical', high: 'badge-high',
  medium: 'badge-medium', low: 'badge-low', informational: 'badge-info',
}
const SCOPE_COLOR: Record<string, string> = {
  in_scope: 'text-severity-low', out_of_scope: 'text-severity-critical', pending: 'text-severity-medium',
}
const TOOLS = ['subfinder','httpx','nmap','nuclei','sqlmap','ghauri','dalfox','ffuf','dirsearch','amass','dnsx','masscan']
const TOOL_PRESETS = [
  { label: 'Recon', tools: ['subfinder','dnsx','httpx','amass'] },
  { label: 'Web',   tools: ['httpx','nuclei','dalfox','ffuf'] },
  { label: 'Full',  tools: ['subfinder','httpx','nmap','nuclei','ffuf'] },
]
const TAGS_OPTIONS = ['Production','Staging','Internal','External','Cloud','API']
const TYPES = ['domain','subdomain','ip','cidr','url','wildcard']
const CRITICALITIES = ['critical','high','medium','low','informational']
const SCOPES = ['in_scope','out_of_scope','pending']
const GROUP_COLORS = [
  '#6366f1','#8b5cf6','#ec4899','#f97316','#eab308',
  '#22c55e','#14b8a6','#06b6d4','#3b82f6','#ef4444',
]

// ── Add Group Modal ───────────────────────────────────────────
function AddGroupModal({ onClose, onSuccess }: { onClose: () => void, onSuccess: () => void }) {
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [color, setColor] = useState('#6366f1')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async () => {
    if (!name.trim()) { toast.error('Group name required'); return }
    setLoading(true)
    try {
      await api.post('/targets/groups', { name: name.trim(), description: desc.trim() || null, color })
      toast.success(`Group "${name}" created`)
      onSuccess(); onClose()
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Failed')
    } finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-default rounded-xl w-full max-w-sm">
        <div className="flex items-center justify-between p-5 border-b border-border-default">
          <h2 className="font-display font-bold text-text-primary flex items-center gap-2">
            <FolderPlus size={16} className="text-accent-primary" /> New Group
          </h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary"><X size={16} /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="label-field">Group Name *</label>
            <input value={name} onChange={e => setName(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              className="input-field" placeholder="e.g. Sprint, Production, BugBounty" autoFocus />
          </div>
          <div>
            <label className="label-field">Description</label>
            <input value={desc} onChange={e => setDesc(e.target.value)}
              className="input-field" placeholder="Optional description" />
          </div>
          <div>
            <label className="label-field mb-2">Color</label>
            <div className="flex gap-2 flex-wrap">
              {GROUP_COLORS.map(c => (
                <button key={c} onClick={() => setColor(c)}
                  className={`w-6 h-6 rounded-full border-2 transition-all ${color === c ? 'border-white scale-110' : 'border-transparent'}`}
                  style={{ backgroundColor: c }} />
              ))}
            </div>
          </div>
        </div>
        <div className="flex gap-3 p-5 border-t border-border-default">
          <button onClick={onClose} className="btn-secondary flex-1">Cancel</button>
          <button onClick={handleSubmit} disabled={loading} className="btn-primary flex-1">
            {loading ? 'Creating...' : 'Create Group'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Quick Scan Modal ──────────────────────────────────────────
function QuickScanModal({ target, onClose }: { target: any, onClose: () => void }) {
  const [selectedTools, setSelectedTools] = useState<string[]>(['subfinder','httpx'])
  const [loading, setLoading] = useState(false)
  const toggleTool = (t: string) => setSelectedTools(prev =>
    prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t]
  )
  const handleScan = async () => {
    if (selectedTools.length === 0) { toast.error('Pilih minimal 1 tool'); return }
    setLoading(true)
    try {
      await api.post('/scans/', {
        target_value: target.value, target_id: target.id,
        scan_mode: 'custom', tools: selectedTools, parameters: {},
      })
      toast.success(`Scan queued → ${target.value}`)
      onClose()
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Failed')
    } finally { setLoading(false) }
  }
  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-default rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between p-5 border-b border-border-default">
          <div>
            <h2 className="font-display font-bold text-text-primary flex items-center gap-2">
              <Zap size={16} className="text-accent-primary" /> Quick Scan
            </h2>
            <p className="font-mono text-xs text-accent-primary mt-0.5">{target.value}</p>
          </div>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary"><X size={16} /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <p className="label-field mb-2">Quick Presets</p>
            <div className="flex gap-2 flex-wrap">
              {TOOL_PRESETS.map(p => (
                <button key={p.label} onClick={() => setSelectedTools(p.tools)}
                  className="btn-secondary text-xs px-3 py-1.5">{p.label}</button>
              ))}
              <button onClick={() => setSelectedTools([])}
                className="text-xs text-text-muted hover:text-text-secondary font-mono">Clear</button>
            </div>
          </div>
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
        <div className="flex gap-3 p-5 border-t border-border-default">
          <button onClick={onClose} className="btn-secondary flex-1">Cancel</button>
          <button onClick={handleScan} disabled={loading || selectedTools.length === 0}
            className="btn-primary flex-1 flex items-center justify-center gap-2">
            <Zap size={13} /> {loading ? 'Queuing...' : 'Launch Scan'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Target Modal ──────────────────────────────────────────────
function TargetModal({ target, groups, onClose, onSuccess }: {
  target?: any, groups: any[], onClose: () => void, onSuccess: () => void
}) {
  const isEdit = !!target
  const [form, setForm] = useState({
    value: target?.value || '',
    type: target?.type || 'domain',
    ip_address: target?.ip_address || '',
    group_id: target?.group_id || '',
    owner: target?.owner || '',
    criticality: target?.criticality || 'medium',
    scope_status: target?.scope_status || 'in_scope',
    tags: (target?.tags || []) as string[],
    notes: target?.notes || '',
  })
  const [loading, setLoading] = useState(false)
  const [resolving, setResolving] = useState(false)
  const resolveTimer = useRef<any>(null)
  const set = (k: string, v: any) => setForm(f => ({ ...f, [k]: v }))
  const toggleTag = (t: string) => set('tags', form.tags.includes(t) ? form.tags.filter((x: string) => x !== t) : [...form.tags, t])

  // Auto-resolve IP
  useEffect(() => {
    const val = form.value.trim()
    if (!val || form.type === 'ip' || form.type === 'cidr' || form.ip_address) return
    if (resolveTimer.current) clearTimeout(resolveTimer.current)
    resolveTimer.current = setTimeout(async () => {
      const hostname = val.replace(/https?:\/\//, '').split('/')[0].split(':')[0]
      if (!hostname || /^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return
      setResolving(true)
      try {
        const res = await api.get(`/targets/resolve/${encodeURIComponent(hostname)}`)
        if (res.data.resolved && res.data.ip) set('ip_address', res.data.ip)
      } catch {}
      finally { setResolving(false) }
    }, 800)
    return () => { if (resolveTimer.current) clearTimeout(resolveTimer.current) }
  }, [form.value, form.type])

  const handleResolve = async () => {
    const hostname = form.value.trim().replace(/https?:\/\//, '').split('/')[0].split(':')[0]
    if (!hostname) return
    setResolving(true)
    try {
      const res = await api.get(`/targets/resolve/${encodeURIComponent(hostname)}`)
      if (res.data.resolved && res.data.ip) {
        set('ip_address', res.data.ip)
        toast.success(`Resolved: ${res.data.ip}`)
      } else toast.error('Could not resolve hostname')
    } catch { toast.error('Resolve failed') }
    finally { setResolving(false) }
  }

  const handleSubmit = async () => {
    if (!form.value.trim()) { toast.error('Target value required'); return }
    setLoading(true)
    const payload = {
      ...form,
      ip_address: form.ip_address.trim() || null,
      group_id: form.group_id || null,
      owner: form.owner.trim() || null,
      notes: form.notes.trim() || null,
    }
    try {
      if (isEdit) {
        await api.patch(`/targets/${target.id}`, payload)
        toast.success('Target updated')
      } else {
        await api.post('/targets/', payload)
        toast.success('Target added')
      }
      onSuccess(); onClose()
    } catch (e: any) {
      toast.error(e.response?.data?.detail || e.message || 'Failed')
    } finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-default rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-5 border-b border-border-default sticky top-0 bg-bg-secondary">
          <h2 className="font-display font-bold text-text-primary flex items-center gap-2">
            {isEdit ? <Edit size={16} className="text-accent-primary" /> : <Plus size={16} className="text-accent-primary" />}
            {isEdit ? `Edit: ${target.value}` : 'Add Target'}
          </h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary"><X size={18} /></button>
        </div>
        <div className="p-5 space-y-4">
          {/* Target Value */}
          <div>
            <label className="label-field">Target Value *</label>
            <input value={form.value} onChange={e => set('value', e.target.value)}
              className="input-field font-mono" placeholder="example.com / 192.168.1.1" />
          </div>

          {/* IP Address */}
          <div>
            <label className="label-field flex items-center gap-2">
              IP Address
              {resolving && <Loader size={11} className="animate-spin text-accent-primary" />}
              {!resolving && form.ip_address && <span className="text-xs font-mono text-severity-low">✓ resolved</span>}
            </label>
            <div className="flex gap-2">
              <input value={form.ip_address} onChange={e => set('ip_address', e.target.value)}
                className="input-field font-mono flex-1" placeholder={resolving ? 'Resolving...' : '0.0.0.0'} />
              <button onClick={handleResolve} disabled={resolving || !form.value}
                className="px-3 rounded-lg border border-border-default text-text-muted hover:border-accent-primary hover:text-accent-primary transition-all">
                {resolving ? <Loader size={13} className="animate-spin" /> : <Globe size={13} />}
              </button>
            </div>
          </div>

          {/* Group */}
          <div>
            <label className="label-field flex items-center gap-2">
              <Folder size={12} className="text-text-muted" /> Group
            </label>
            <select value={form.group_id} onChange={e => set('group_id', e.target.value)} className="input-field">
              <option value="">— No Group —</option>
              {groups.map((g: any) => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </select>
          </div>

          {/* Type + Owner */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label-field">Type</label>
              <select value={form.type} onChange={e => set('type', e.target.value)} className="input-field">
                {TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="label-field">Owner</label>
              <input value={form.owner} onChange={e => set('owner', e.target.value)}
                className="input-field" placeholder="Team name" />
            </div>
          </div>

          {/* Criticality + Scope */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label-field">Criticality</label>
              <select value={form.criticality} onChange={e => set('criticality', e.target.value)} className="input-field">
                {CRITICALITIES.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="label-field">Scope</label>
              <select value={form.scope_status} onChange={e => set('scope_status', e.target.value)} className="input-field">
                {SCOPES.map(s => <option key={s} value={s}>{s.replace('_',' ')}</option>)}
              </select>
            </div>
          </div>

          {/* Tags */}
          <div>
            <label className="label-field mb-2">Tags</label>
            <div className="flex flex-wrap gap-2">
              {TAGS_OPTIONS.map(t => (
                <button key={t} onClick={() => toggleTag(t)}
                  className={`text-xs font-mono px-3 py-1.5 rounded border transition-all ${
                    form.tags.includes(t)
                      ? 'bg-accent-primary bg-opacity-10 border-accent-primary text-accent-primary'
                      : 'border-border-default text-text-muted hover:border-border-muted'
                  }`}>{t}</button>
              ))}
            </div>
          </div>

          {/* Notes */}
          <div>
            <label className="label-field">Notes</label>
            <textarea value={form.notes} onChange={e => set('notes', e.target.value)}
              className="input-field h-20 resize-none" placeholder="Additional notes..." />
          </div>
        </div>
        <div className="flex gap-3 p-5 border-t border-border-default">
          <button onClick={onClose} className="btn-secondary flex-1">Cancel</button>
          <button onClick={handleSubmit} disabled={loading} className="btn-primary flex-1">
            {loading ? 'Saving...' : isEdit ? 'Save Changes' : 'Add Target'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Action Dropdown ───────────────────────────────────────────
function ActionMenu({ onScan, onEdit, onDuplicate, onDelete }: {
  onScan: () => void, onEdit: () => void, onDuplicate: () => void, onDelete: () => void
}) {
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState({ top: 0, right: 0 })
  const btnRef = useRef<HTMLButtonElement>(null)
  const handleOpen = (e: React.MouseEvent) => {
    e.stopPropagation()
    if (!open && btnRef.current) {
      const rect = btnRef.current.getBoundingClientRect()
      setPos({ top: rect.bottom + 4, right: window.innerWidth - rect.right })
    }
    setOpen(!open)
  }
  return (
    <div onClick={e => e.stopPropagation()}>
      <button ref={btnRef} onClick={handleOpen}
        className="flex items-center gap-1 text-xs font-mono text-text-muted hover:text-text-primary border border-border-default hover:border-border-muted px-2 py-1.5 rounded transition-all">
        Actions <ChevronDown size={10} />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="fixed z-50 bg-bg-secondary border border-border-default rounded-lg shadow-2xl min-w-44 py-1"
            style={{ top: pos.top, right: pos.right }}>
            <button onClick={() => { setOpen(false); onScan() }}
              className="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs font-mono text-accent-primary hover:bg-bg-hover transition-colors">
              <Zap size={12} /> Scan Target
            </button>
            <button onClick={() => { setOpen(false); onEdit() }}
              className="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs font-mono text-text-secondary hover:bg-bg-hover transition-colors">
              <Edit size={12} /> Edit
            </button>
            <button onClick={() => { setOpen(false); onDuplicate() }}
              className="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs font-mono text-text-secondary hover:bg-bg-hover transition-colors">
              <Copy size={12} /> Duplicate
            </button>
            <div className="border-t border-border-default my-1" />
            <button onClick={() => { setOpen(false); onDelete() }}
              className="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs font-mono text-severity-critical hover:bg-bg-hover transition-colors">
              <Trash2 size={12} /> Delete
            </button>
          </div>
        </>
      )}
    </div>
  )
}

// ── Export Button ─────────────────────────────────────────────
function ExportMenu({ groupId }: { groupId?: string }) {
  const [open, setOpen] = useState(false)

  const doExport = async (fmt: string) => {
    setOpen(false)
    const params: Record<string, string> = { format: fmt }
    if (groupId) params.group_id = groupId
    try {
      const res = await api.get('/targets/export', { params, responseType: 'blob' })
      const ext = fmt === 'xlsx' ? 'xlsx' : fmt === 'csv' ? 'csv' : 'txt'
      const url = URL.createObjectURL(new Blob([res.data]))
      const a = document.createElement('a')
      a.href = url; a.download = `targets.${ext}`; a.click()
      URL.revokeObjectURL(url)
    } catch { toast.error('Export failed') }
  }

  return (
    <div className="relative">
      <button onClick={() => setOpen(!open)}
        className="btn-secondary flex items-center gap-2 text-sm">
        <Download size={14} /> Export
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full mt-1 z-50 bg-bg-secondary border border-border-default rounded-lg shadow-xl min-w-36 py-1">
            {[['txt','TXT — plain list'],['csv','CSV — with metadata'],['xlsx','Excel — formatted']].map(([fmt, label]) => (
              <button key={fmt} onClick={() => doExport(fmt)}
                className="w-full text-left px-4 py-2.5 text-xs font-mono text-text-secondary hover:bg-bg-hover transition-colors">
                {label}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────
export default function TargetsPage() {
  const [search, setSearch] = useState('')
  const [filterCrit, setFilterCrit] = useState('')
  const [filterGroup, setFilterGroup] = useState('')
  const [view, setView] = useState<'table' | 'card'>('table')
  const [showAdd, setShowAdd] = useState(false)
  const [showAddGroup, setShowAddGroup] = useState(false)
  const [editTarget, setEditTarget] = useState<any>(null)
  const [scanTarget, setScanTarget] = useState<any>(null)
  const queryClient = useQueryClient()

  const { data: groupsData = [] } = useQuery({
    queryKey: ['target-groups'],
    queryFn: () => api.get('/targets/groups').then(r => r.data),
  })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['targets', search, filterCrit, filterGroup],
    queryFn: () => api.get('/targets/', {
      params: {
        search: search || undefined,
        criticality: filterCrit || undefined,
        group_id: filterGroup || undefined,
        limit: 200,
      }
    }).then(r => r.data),
  })

  const deleteGroupMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/targets/groups/${id}`),
    onSuccess: () => {
      toast.success('Group deleted')
      queryClient.invalidateQueries({ queryKey: ['target-groups'] })
      queryClient.invalidateQueries({ queryKey: ['targets'] })
      setFilterGroup('')
    },
    onError: () => toast.error('Failed to delete group'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/targets/${id}`),
    onSuccess: () => { toast.success('Target deleted'); queryClient.invalidateQueries({ queryKey: ['targets'] }) },
    onError: () => toast.error('Failed to delete'),
  })

  const duplicateMutation = useMutation({
    mutationFn: (t: any) => api.post('/targets/', {
      value: `${t.value}-copy`, type: t.type, ip_address: t.ip_address,
      group_id: t.group_id, owner: t.owner, criticality: t.criticality,
      scope_status: t.scope_status, tags: t.tags, notes: t.notes,
    }),
    onSuccess: () => { toast.success('Duplicated'); queryClient.invalidateQueries({ queryKey: ['targets'] }) },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed'),
  })

  const onSuccess = () => {
    queryClient.invalidateQueries({ queryKey: ['targets'] })
    queryClient.invalidateQueries({ queryKey: ['target-groups'] })
  }

  const targets = data?.items || []
  const groups: any[] = groupsData

  return (
    <div className="space-y-5 animate-fade-in">
      {scanTarget && <QuickScanModal target={scanTarget} onClose={() => setScanTarget(null)} />}
      {(showAdd || editTarget) && (
        <TargetModal target={editTarget} groups={groups}
          onClose={() => { setShowAdd(false); setEditTarget(null) }} onSuccess={onSuccess} />
      )}
      {showAddGroup && (
        <AddGroupModal onClose={() => setShowAddGroup(false)} onSuccess={onSuccess} />
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
            <Target size={24} className="text-accent-primary" /> Targets
          </h1>
          <p className="text-text-muted text-sm font-mono mt-1">
            {isLoading ? '...' : `${data?.total || 0} targets`}
            {filterGroup && groups.find((g: any) => g.id === filterGroup) &&
              ` in ${groups.find((g: any) => g.id === filterGroup).name}`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="btn-secondary p-2"><RefreshCw size={14} /></button>
          <ExportMenu groupId={filterGroup || undefined} search={search || undefined} filterCrit={filterCrit || undefined} filterType={filterTypes.length === 1 ? filterTypes[0] : undefined} />
          <button onClick={() => setShowAddGroup(true)}
            className="btn-secondary flex items-center gap-2 text-sm">
            <FolderPlus size={14} /> New Group
          </button>
          <button onClick={() => setShowAdd(true)} className="btn-primary flex items-center gap-2">
            <Plus size={14} /> Add Target
          </button>
        </div>
      </div>

      {/* Group tabs */}
      {groups.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <button onClick={() => setFilterGroup('')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition-all ${
              !filterGroup ? 'border-accent-primary text-accent-primary bg-accent-primary bg-opacity-10' : 'border-border-default text-text-muted hover:border-border-muted'
            }`}>
            All <span className="ml-1 opacity-60">{data?.total || 0}</span>
          </button>
          {groups.map((g: any) => (
            <div key={g.id} className="flex items-center gap-0.5 group/grp">
              <button onClick={() => setFilterGroup(g.id === filterGroup ? '' : g.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition-all flex items-center gap-1.5 ${
                  filterGroup === g.id
                    ? 'border-opacity-80 text-white bg-opacity-20'
                    : 'border-border-default text-text-muted hover:border-border-muted'
                }`}
                style={filterGroup === g.id ? { borderColor: g.color, backgroundColor: g.color + '30', color: g.color } : {}}>
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: g.color }} />
                {g.name}
                <span className="opacity-60">{g.target_count}</span>
              </button>
              <button
                onClick={() => {
                  if (confirm(`Delete group "${g.name}"? Targets will be unassigned.`))
                    deleteGroupMutation.mutate(g.id)
                }}
                className="opacity-0 group-hover/grp:opacity-100 p-1 text-text-muted hover:text-severity-critical transition-all"
                title="Delete group">
                <X size={11} />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="card p-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search targets..." className="input-field pl-9" />
        </div>
        <select value={filterCrit} onChange={e => setFilterCrit(e.target.value)} className="input-field w-40">
          <option value="">All criticality</option>
          {CRITICALITIES.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <div className="flex items-center gap-1 border border-border-default rounded-lg p-1">
          <button onClick={() => setView('table')} className={`p-1.5 rounded ${view === 'table' ? 'bg-bg-hover text-accent-primary' : 'text-text-muted'}`}><List size={14} /></button>
          <button onClick={() => setView('card')} className={`p-1.5 rounded ${view === 'card' ? 'bg-bg-hover text-accent-primary' : 'text-text-muted'}`}><Grid size={14} /></button>
        </div>
      </div>

      {/* Content */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-accent-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : targets.length === 0 ? (
        <div className="card p-16 text-center">
          <Target size={40} className="text-text-muted mx-auto mb-3" />
          <p className="text-text-secondary">No targets yet.</p>
          <button onClick={() => setShowAdd(true)} className="btn-primary mt-4 inline-flex items-center gap-2">
            <Plus size={14} /> Add First Target
          </button>
        </div>
      ) : view === 'table' ? (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border-default">
                {['Target','IP Address','Group','Type','Criticality','Scope','Actions'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-text-muted text-xs font-mono uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border-default">
              {targets.map((t: any) => (
                <tr key={t.id} className="hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-3 max-w-xs">
                    <p className="font-mono text-sm text-text-primary truncate">{t.value}</p>
                    {t.notes && <p className="text-xs text-text-muted truncate mt-0.5">{t.notes}</p>}
                  </td>
                  <td className="px-4 py-3">
                    {t.ip_address
                      ? <span className="font-mono text-xs text-accent-primary flex items-center gap-1">
                          <Server size={10} className="text-text-muted flex-shrink-0" />{t.ip_address}
                        </span>
                      : <span className="text-text-muted text-xs">—</span>
                    }
                  </td>
                  <td className="px-4 py-3">
                    {t.group
                      ? <span className="text-xs font-mono px-2 py-0.5 rounded-full border"
                          style={{ borderColor: t.group.color, color: t.group.color, backgroundColor: t.group.color + '20' }}>
                          {t.group.name}
                        </span>
                      : <span className="text-text-muted text-xs">—</span>
                    }
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-mono text-text-secondary bg-bg-tertiary border border-border-default px-2 py-0.5 rounded">{t.type}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={CRIT_COLOR[t.criticality]}>{t.criticality}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-mono ${SCOPE_COLOR[t.scope_status]}`}>
                      {t.scope_status?.replace('_',' ')}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <ActionMenu
                      onScan={() => setScanTarget(t)} onEdit={() => setEditTarget(t)}
                      onDuplicate={() => duplicateMutation.mutate(t)}
                      onDelete={() => { if (confirm(`Delete "${t.value}"?`)) deleteMutation.mutate(t.id) }}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {targets.map((t: any) => (
            <div key={t.id} className="card p-4 hover:border-border-muted transition-colors"
              style={t.group ? { borderLeftColor: t.group.color, borderLeftWidth: 3 } : {}}>
              <div className="flex items-start justify-between mb-2">
                <div className="flex-1 min-w-0">
                  <p className="font-mono text-sm text-text-primary truncate font-medium">{t.value}</p>
                  {t.ip_address && (
                    <p className="font-mono text-xs text-accent-primary flex items-center gap-1 mt-0.5">
                      <Server size={10} className="text-text-muted" />{t.ip_address}
                    </p>
                  )}
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <span className="text-xs font-mono text-text-muted bg-bg-tertiary border border-border-default px-1.5 py-0.5 rounded">{t.type}</span>
                    {t.group && (
                      <span className="text-xs font-mono px-1.5 py-0.5 rounded border"
                        style={{ borderColor: t.group.color, color: t.group.color, backgroundColor: t.group.color + '20' }}>
                        {t.group.name}
                      </span>
                    )}
                  </div>
                </div>
                <span className={`${CRIT_COLOR[t.criticality]} ml-2 flex-shrink-0`}>{t.criticality}</span>
              </div>
              <div className="flex items-center gap-2 pt-3 border-t border-border-default">
                <button onClick={() => setScanTarget(t)}
                  className="flex-1 flex items-center justify-center gap-1.5 text-xs font-mono text-accent-primary border border-accent-primary border-opacity-40 hover:bg-accent-primary hover:bg-opacity-10 py-1.5 rounded transition-colors">
                  <Zap size={11} /> Scan
                </button>
                <button onClick={() => setEditTarget(t)}
                  className="p-1.5 text-text-muted hover:text-text-primary border border-border-default rounded transition-colors">
                  <Edit size={13} />
                </button>
                <button onClick={() => duplicateMutation.mutate(t)}
                  className="p-1.5 text-text-muted hover:text-text-primary border border-border-default rounded transition-colors">
                  <Copy size={13} />
                </button>
                <button onClick={() => { if (confirm(`Delete "${t.value}"?`)) deleteMutation.mutate(t.id) }}
                  className="p-1.5 text-text-muted hover:text-severity-critical border border-border-default rounded transition-colors">
                  <Trash2 size={13} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
 
