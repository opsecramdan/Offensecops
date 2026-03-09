import { useState, useRef, useEffect } from 'react'
import { X, Plus, Trash2, Upload, Download, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'

const SEV_COLOR: Record<string,string> = {
  critical:'#ff5f5f', high:'#ff9f43', medium:'#ffd43b', low:'#a9e34b', informational:'#74c7ec'
}

interface Props {
  vulnItem: any
  existingPocs: any[]
  onClose: () => void
  onRefresh: () => void
}

export default function PocModal({ vulnItem, existingPocs, onClose, onRefresh }: Props) {
  const [pocs, setPocs] = useState<any[]>(existingPocs)
  const [activePocId, setActivePocId] = useState<string|null>(existingPocs[0]?.id || null)
  const [creating, setCreating] = useState(existingPocs.length === 0)

  // Sync when existingPocs prop changes (different vuln clicked)
  useEffect(() => {
    setPocs(existingPocs)
    setActivePocId(existingPocs[0]?.id || null)
    setCreating(existingPocs.length === 0)
    setActiveTab(existingPocs.length === 0 ? 'form' : 'list')
  }, [vulnItem.id])
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState<any>({
    status: 'BELUM DIPERBAIKI',
    description: '',
    poc_steps: '',
    reference: vulnItem.referensi || '',
    recommendation: '',
  })
  const [evidences, setEvidences] = useState<any[]>([{id: null, label:'Evidence-01', caption:'', file:null, preview:null}])
  const [retestings, setRetestings] = useState<any[]>([])
  const [showAddRetest, setShowAddRetest] = useState(false)
  const [newRetest, setNewRetest] = useState({ retest_date:'', result:'', status:'BELUM DIPERBAIKI' })
  const [activeTab, setActiveTab] = useState<'form'|'preview'|'list'>('list')
  const fileRefs = useRef<Record<number, HTMLInputElement|null>>({})

  const activePoc = pocs.find((p:any) => p.id === activePocId)

  // Load existing poc into form when switching to edit tab
  const handleEditPoc = (poc: any) => {
    setForm({
      status: poc.status || 'BELUM DIPERBAIKI',
      description: poc.description || '',
      poc_steps: poc.poc_steps || '',
      reference: poc.reference || '',
      recommendation: poc.recommendation || '',
    })
    // Load existing evidences - preserve uploaded ones, show existing as preview
    const existingEvs = poc.evidences?.length > 0
      ? poc.evidences.map((e:any) => ({
          id: e.id,
          label: e.label || 'Evidence-01',
          caption: e.caption || '',
          file: null,  // no new file
          preview: e.url || null,  // show existing image
          existing: true,  // mark as already saved
        }))
      : [{id: null, label:'Evidence-01', caption:'', file:null, preview:null, existing:false}]
    setEvidences(existingEvs)
    setActivePocId(poc.id)
    setCreating(false)
    setActiveTab('form')
  }

  const loadPoc = async (pocId: string) => {
    const res = await api.get(`/poc/${pocId}`)
    setPocs(prev => prev.map(p => p.id === pocId ? res.data : p))
    return res.data
  }

  const handleSaveEdit = async () => {
    if (!activePocId) return
    setSaving(true)
    try {
      await api.put(`/poc/${activePocId}`, {
        status: form.status,
        description: form.description,
        poc_steps: form.poc_steps,
        reference: form.reference,
        recommendation: form.recommendation,
      })
      // Upload only NEW evidences (not existing ones)
      for (let i = 0; i < evidences.length; i++) {
        const ev = evidences[i]
        if (!ev.file || ev.existing) continue
        const fd = new FormData()
        fd.append('file', ev.file)
        fd.append('label', ev.label)
        fd.append('caption', ev.caption)
        fd.append('order_no', String(i + 1))
        await api.post(`/poc/${activePocId}/evidence`, fd, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })
      }
      const full = await loadPoc(activePocId)
      // Force update pocs list with fresh data
      setPocs((prev:any) => {
        const exists = prev.find((p:any) => p.id === activePocId)
        if (exists) return prev.map((p:any) => p.id === activePocId ? full : p)
        return [...prev, full]
      })
      // Reset evidences from fresh data
      setEvidences(full.evidences?.length > 0
        ? full.evidences.map((e:any) => ({id:e.id, label:e.label, caption:e.caption||'', file:null, preview:e.url||null, existing:true}))
        : [{id:null, label:'Evidence-01', caption:'', file:null, preview:null, existing:false}])
      setActiveTab('preview')
      toast.success('POC updated!')
      onRefresh()
    } catch(e: any) {
      toast.error('Failed to update')
    } finally {
      setSaving(false)
    }
  }

  const handleDeletePoc = async (pocId: string) => {
    if (!confirm('Delete this POC?')) return
    try {
      await api.delete(`/poc/${pocId}`)
      const updated = pocs.filter((p:any) => p.id !== pocId)
      setPocs(updated)
      if (activePocId === pocId) {
        setActivePocId(updated[0]?.id || null)
        setActiveTab(updated.length === 0 ? 'form' : 'list')
        if (updated.length === 0) setCreating(true)
      }
      toast.success('POC deleted')
      onRefresh()
    } catch(e: any) {
      toast.error('Failed to delete')
    }
  }

  const handleCreatePoc = async () => {
    setSaving(true)
    try {
      const res = await api.post('/poc', {
        vuln_report_id: vulnItem.id,
        ...form,
      })
      const newPoc = res.data

      // Upload evidences
      for (let i = 0; i < evidences.length; i++) {
        const ev = evidences[i]
        if (!ev.file) continue
        const fd = new FormData()
        fd.append('file', ev.file)
        fd.append('label', ev.label)
        fd.append('caption', ev.caption)
        fd.append('order_no', String(i + 1))
        await api.post(`/poc/${newPoc.id}/evidence`, fd, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })
      }

      // Reload with evidences
      const full = await loadPoc(newPoc.id)
      setPocs(prev => [...prev, full])
      setActivePocId(newPoc.id)
      setCreating(false)
      setActiveTab('preview')
      toast.success('POC created!')
      onRefresh()
    } catch(e: any) {
      toast.error(e.response?.data?.detail || 'Failed')
    } finally {
      setSaving(false)
    }
  }

  const handleAddEvidence = () => {
    const n = evidences.length + 1
    setEvidences(p => [...p, {id:null, label:`Evidence-0${n}`, caption:'', file:null, preview:null}])
  }

  const handleFileChange = (idx: number, file: File) => {
    const reader = new FileReader()
    reader.onload = (e) => {
      setEvidences(prev => prev.map((ev, i) => i === idx ? {...ev, file, preview: e.target?.result} : ev))
    }
    reader.readAsDataURL(file)
  }

  const handleAddRetest = async () => {
    if (!activePocId) return
    try {
      const res = await api.post(`/poc/${activePocId}/retest`, { poc_id: activePocId, ...newRetest })
      setRetestings(p => [...p, res.data])
      setShowAddRetest(false)
      setNewRetest({ retest_date:'', result:'', status:'BELUM DIPERBAIKI' })
      await loadPoc(activePocId)
      toast.success('Retesting added')
    } catch(e: any) {
      toast.error('Failed to add retesting')
    }
  }

  const handleUploadRetestEvidence = async (retestId: string, file: File, label: string, caption: string, orderNo: number) => {
    const fd = new FormData()
    fd.append('file', file)
    fd.append('label', label)
    fd.append('caption', caption)
    fd.append('order_no', String(orderNo))
    await api.post(`/poc/retest/${retestId}/evidence`, fd, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    await loadPoc(activePocId!)
  }

  const handleExportWord = () => {
    if (!activePocId) return
    const authRaw = localStorage.getItem('offensecops-auth')
    const token = authRaw ? JSON.parse(authRaw)?.state?.accessToken : ''
    window.open(`/api/poc/${activePocId}/export-word?token=${token}`)
  }

  const handleExportPdf = () => {
    if (!activePocId) return
    const authRaw = localStorage.getItem('offensecops-auth')
    const token = authRaw ? JSON.parse(authRaw)?.state?.accessToken : ''
    window.open(`/api/poc/${activePocId}/export-pdf?token=${token}`)
  }

  const sevColor = SEV_COLOR[(vulnItem.severity||'medium').toLowerCase()] || '#74c7ec'
  const statusColor = (s: string) => s === 'DIPERBAIKI' ? '#a9e34b' : '#ff5f5f'

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 z-50 flex items-center justify-center p-4"
      onClick={onClose}>
      <div className="card w-full max-w-4xl max-h-[95vh] flex flex-col"
        onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-border-default flex-shrink-0">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded"
                style={{background: sevColor+'20', color: sevColor}}>
                {vulnItem.severity?.toUpperCase()}
              </span>
              <span className="text-xs font-mono text-text-muted">{vulnItem.vuln_id}</span>
            </div>
            <h2 className="text-sm font-mono font-bold text-text-primary">{vulnItem.vuln_name}</h2>
          </div>
          <div className="flex items-center gap-2">
            {activePocId && (
              <>
            <button onClick={handleExportPdf}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono border border-border-default text-text-muted hover:text-accent-primary transition-all">
                <Download size={12} /> Export PDF
              </button>
              <button onClick={handleExportWord}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono border border-border-default text-text-muted hover:text-severity-low transition-all">
                <Download size={12} /> Export Word
              </button>
            </>
            )}
            <button onClick={() => { setCreating(true); setActiveTab('form'); setActivePocId(null) }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono btn-primary">
              <Plus size={12} /> New POC
            </button>
            <button onClick={onClose}><X size={16} className="text-text-muted" /></button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 px-5 pt-3 flex-shrink-0">
          {pocs.length > 0 && (
            <button onClick={() => setActiveTab('list')}
              className={`px-3 py-1.5 rounded text-xs font-mono font-bold transition-all ${activeTab==='list' ? 'bg-accent-primary bg-opacity-20 text-accent-primary border border-accent-primary border-opacity-40' : 'text-text-muted border border-transparent'}`}>
              POC List ({pocs.length})
            </button>
          )}
          {(creating || activePocId) && (
            <>
              <button onClick={() => setActiveTab('form')}
                className={`px-3 py-1.5 rounded text-xs font-mono font-bold transition-all ${activeTab==='form' ? 'bg-accent-primary bg-opacity-20 text-accent-primary border border-accent-primary border-opacity-40' : 'text-text-muted border border-transparent'}`}>
                {creating ? 'New POC' : 'Edit'}
              </button>
              {activePocId && (
                <button onClick={() => setActiveTab('preview')}
                  className={`px-3 py-1.5 rounded text-xs font-mono font-bold transition-all ${activeTab==='preview' ? 'bg-accent-primary bg-opacity-20 text-accent-primary border border-accent-primary border-opacity-40' : 'text-text-muted border border-transparent'}`}>
                  Preview
                </button>
              )}
            </>
          )}
        </div>

        {/* Body */}
        <div className="flex-1 min-h-0 overflow-y-auto p-5 space-y-4">

          {/* POC List */}
          {activeTab === 'list' && (
            <div className="space-y-3">
              {pocs.length === 0 && (
                <div className="text-center py-8">
                  <p className="text-text-muted font-mono text-xs">Belum ada POC — klik "New POC" untuk membuat</p>
                </div>
              )}
              {pocs.map((poc, i) => (
                <div key={poc.id} className="card p-4 space-y-2 cursor-pointer hover:border-accent-primary transition-all"
                  onClick={() => { setActivePocId(poc.id); setActiveTab('preview') }}
                  onDoubleClick={() => handleEditPoc(poc)}>
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-mono font-bold text-text-primary">POC #{i+1}</p>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono px-2 py-0.5 rounded font-bold"
                        style={{background: statusColor(poc.status)+'20', color: statusColor(poc.status)}}>
                        {poc.status}
                      </span>
                      <span className="text-xs font-mono text-text-muted">
                        {poc.created_at ? new Date(poc.created_at).toLocaleDateString() : ''}
                      </span>
                      <button onClick={e => { e.stopPropagation(); handleDeletePoc(poc.id) }}
                        className="p-1 text-text-muted hover:text-severity-critical transition-colors" title="Delete POC">
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </div>
                  <p className="text-xs font-mono text-text-muted line-clamp-2">{poc.description || 'No description'}</p>
                  <div className="flex items-center gap-3 text-xs font-mono text-text-muted">
                    <span>📎 {poc.evidences?.length || 0} evidence</span>
                    <span>🔄 {poc.retestings?.length || 0} retesting</span>
                    <button onClick={e => { e.stopPropagation(); handleEditPoc(poc) }}
                      className="ml-auto flex items-center gap-1 px-2 py-0.5 rounded border border-border-default text-text-muted hover:text-accent-primary hover:border-accent-primary transition-all">
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                      Edit
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Form */}
          {activeTab === 'form' && (
            <div className="space-y-4">
              {/* Auto-filled info */}
              <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-bg-tertiary">
                <div>
                  <p className="text-xs font-mono text-text-muted">Vulnerability ID</p>
                  <p className="text-xs font-mono font-bold text-accent-primary">{vulnItem.vuln_id || '-'}</p>
                </div>
                <div>
                  <p className="text-xs font-mono text-text-muted">CVSS Score</p>
                  <p className="text-xs font-mono font-bold text-text-primary">{vulnItem.cvss_score || '-'}</p>
                </div>
                <div className="col-span-2">
                  <p className="text-xs font-mono text-text-muted">Vulnerability Name</p>
                  <p className="text-xs font-mono font-bold text-text-primary">{vulnItem.vuln_name}</p>
                </div>
              </div>

              {/* Status */}
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block font-bold">Status</label>
                <div className="flex gap-2">
                  {['BELUM DIPERBAIKI', 'DIPERBAIKI'].map(s => (
                    <button key={s} onClick={() => setForm((p:any) => ({...p, status: s}))}
                      className={`px-3 py-1.5 rounded text-xs font-mono font-bold transition-all ${
                        form.status === s
                          ? `border` : 'border border-border-default text-text-muted'
                      }`}
                      style={form.status === s ? {
                        borderColor: statusColor(s)+'80',
                        background: statusColor(s)+'15',
                        color: statusColor(s)
                      } : {}}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>

              {/* Description */}
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block font-bold">Description</label>
                <textarea value={form.description} onChange={e=>setForm((p:any)=>({...p,description:e.target.value}))}
                  rows={4} placeholder="Deskripsi Kerentanan..."
                  className="input-field font-mono text-xs w-full resize-none" />
              </div>

              {/* POC Steps */}
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block font-bold">Proof of Concept (Steps)</label>
                <textarea value={form.poc_steps} onChange={e=>setForm((p:any)=>({...p,poc_steps:e.target.value}))}
                  rows={5} placeholder={"1. Login sebagai role PIC\n2. Akses URL...\n3. Berhasil menampilkan..."}
                  className="input-field font-mono text-xs w-full resize-none" />
              </div>

              {/* Evidences */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-xs font-mono text-text-muted font-bold">Evidence</label>
                  <button onClick={handleAddEvidence}
                    className="flex items-center gap-1 text-xs font-mono text-accent-primary hover:opacity-80">
                    <Plus size={11} /> Add Evidence
                  </button>
                </div>
                <div className="space-y-3">
                  {evidences.map((ev, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-bg-tertiary space-y-2">
                      <div className="flex items-center gap-2">
                        <input value={ev.label} onChange={e => setEvidences(p => p.map((e2,i) => i===idx ? {...e2,label:e.target.value} : e2))}
                          className="input-field font-mono text-xs w-32" placeholder="Evidence-01" />
                        <button onClick={() => setEvidences(p => p.filter((_,i) => i!==idx))}
                          className="text-text-muted hover:text-severity-critical transition-colors ml-auto">
                          <Trash2 size={12} />
                        </button>
                      </div>
                      <input value={ev.caption} onChange={e => setEvidences(p => p.map((e2,i) => i===idx ? {...e2,caption:e.target.value} : e2))}
                        className="input-field font-mono text-xs w-full" placeholder="Caption / keterangan..." />
                      <input ref={el => fileRefs.current[idx] = el} type="file"
                        accept=".png,.jpg,.jpeg" className="hidden"
                        onChange={e => { if(e.target.files?.[0]) handleFileChange(idx, e.target.files[0]) }} />
                      {ev.preview ? (
                        <div className="relative">
                          <img src={ev.preview} alt={ev.label} className="w-full max-h-48 object-contain rounded border border-border-default" />
                          <div className="absolute top-1 right-1 flex gap-1">
                            {ev.existing && (
                              <span className="bg-bg-tertiary text-text-muted text-xs px-1 rounded font-mono">saved</span>
                            )}
                            <button onClick={async () => {
                              if (ev.existing && ev.id) {
                                await api.delete(`/poc/evidence/${ev.id}`)
                                // Reload poc to sync
                                const updated = await loadPoc(activePocId!)
                                setPocs((prev:any) => prev.map((p:any) => p.id === activePocId ? updated : p))
                                // Update evidences list
                                setEvidences(updated.evidences?.length > 0
                                  ? updated.evidences.map((e:any) => ({id:e.id, label:e.label, caption:e.caption||'', file:null, preview:e.url||null, existing:true}))
                                  : [{id:null, label:'Evidence-01', caption:'', file:null, preview:null, existing:false}])
                              } else {
                                setEvidences((p:any) => p.filter((_:any, i:number) => i !== idx))
                              }
                            }} className="bg-severity-critical text-white rounded p-0.5">
                              <X size={10} />
                            </button>
                          </div>
                          <button onClick={() => fileRefs.current[idx]?.click()}
                            className="mt-1 w-full py-1 rounded border border-dashed border-border-default text-xs font-mono text-text-muted hover:border-accent-primary transition-all">
                            Replace Image
                          </button>
                        </div>
                      ) : (
                        <button onClick={() => fileRefs.current[idx]?.click()}
                          className="w-full py-3 rounded border border-dashed border-border-default text-xs font-mono text-text-muted hover:border-accent-primary hover:text-accent-primary transition-all flex items-center justify-center gap-2">
                          <Upload size={12} /> Upload Image (PNG/JPG/JPEG)
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Reference - auto filled */}
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block font-bold">Reference <span className="opacity-60">(auto-filled)</span></label>
                <textarea value={form.reference} onChange={e=>setForm((p:any)=>({...p,reference:e.target.value}))}
                  rows={3} className="input-field font-mono text-xs w-full resize-none" />
              </div>

              {/* Recommendation */}
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block font-bold">Recommendation</label>
                <textarea value={form.recommendation} onChange={e=>setForm((p:any)=>({...p,recommendation:e.target.value}))}
                  rows={4} placeholder="Batasi akses ke endpoint sensitif..."
                  className="input-field font-mono text-xs w-full resize-none" />
              </div>

              <button onClick={creating ? handleCreatePoc : handleSaveEdit} disabled={saving}
                className="w-full btn-primary py-2.5 font-mono font-bold rounded-lg disabled:opacity-50">
                {saving ? 'Saving...' : creating ? 'Save POC' : 'Update POC'}
              </button>
            </div>
          )}

          {/* Preview */}
          {activeTab === 'preview' && activePoc && (
            <div className="space-y-5 font-mono">
              {/* Info grid */}
              <div className="grid grid-cols-2 gap-3 p-4 rounded-lg bg-bg-tertiary">
                <div>
                  <p className="text-xs text-text-muted">Vulnerability ID</p>
                  <p className="text-xs font-bold text-accent-primary">{activePoc.vuln_id || '-'}</p>
                </div>
                <div>
                  <p className="text-xs text-text-muted">Severity</p>
                  <p className="text-xs font-bold" style={{color: SEV_COLOR[(activePoc.severity||'').toLowerCase()]}}>{activePoc.severity?.toUpperCase() || '-'}</p>
                </div>
                <div className="col-span-2">
                  <p className="text-xs text-text-muted">Vulnerability Name</p>
                  <p className="text-xs font-bold text-text-primary">{activePoc.vuln_name || '-'}</p>
                </div>
                <div className="col-span-2">
                  <p className="text-xs text-text-muted">CVSS Vector</p>
                  <p className="text-xs text-accent-primary break-all">{activePoc.cvss_vector || '-'}</p>
                </div>
                <div>
                  <p className="text-xs text-text-muted">Status</p>
                  <p className="text-xs font-bold" style={{color: statusColor(activePoc.status)}}>{activePoc.status}</p>
                </div>
                <div>
                  <p className="text-xs text-text-muted">Tanggal</p>
                  <p className="text-xs text-text-primary">{activePoc.created_at ? new Date(activePoc.created_at).toLocaleDateString('id-ID') : '-'}</p>
                </div>
              </div>

              {/* Description */}
              {activePoc.description && (
                <div>
                  <p className="text-xs font-bold text-text-muted mb-2 uppercase tracking-wider">Description</p>
                  <p className="text-xs text-text-primary leading-relaxed whitespace-pre-wrap bg-bg-tertiary p-3 rounded-lg">{activePoc.description}</p>
                </div>
              )}

              {/* POC Steps */}
              {activePoc.poc_steps && (
                <div>
                  <p className="text-xs font-bold text-text-muted mb-2 uppercase tracking-wider">Proof of Concept</p>
                  <p className="text-xs text-text-primary leading-relaxed whitespace-pre-wrap bg-bg-tertiary p-3 rounded-lg">{activePoc.poc_steps}</p>
                </div>
              )}

              {/* Evidences */}
              {activePoc.evidences?.length > 0 && (
                <div>
                  <p className="text-xs font-bold text-text-muted mb-2 uppercase tracking-wider">Evidence</p>
                  <div className="space-y-3">
                    {activePoc.evidences.map((ev: any) => (
                      <div key={ev.id} className="p-3 rounded-lg bg-bg-tertiary space-y-2">
                        <p className="text-xs font-bold text-accent-primary">{ev.label}</p>
                        {ev.caption && <p className="text-xs text-text-muted">{ev.caption}</p>}
                        {ev.url && <img src={ev.url} alt={ev.label} className="w-full max-h-64 object-contain rounded border border-border-default" />}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Reference */}
              {activePoc.reference && (
                <div>
                  <p className="text-xs font-bold text-text-muted mb-2 uppercase tracking-wider">Reference</p>
                  <p className="text-xs text-text-primary leading-relaxed whitespace-pre-wrap bg-bg-tertiary p-3 rounded-lg">{activePoc.reference}</p>
                </div>
              )}

              {/* Recommendation */}
              {activePoc.recommendation && (
                <div>
                  <p className="text-xs font-bold text-text-muted mb-2 uppercase tracking-wider">Recommendation</p>
                  <p className="text-xs text-text-primary leading-relaxed whitespace-pre-wrap bg-bg-tertiary p-3 rounded-lg">{activePoc.recommendation}</p>
                </div>
              )}

              {/* Retestings */}
              {activePoc.retestings?.length > 0 && activePoc.retestings.map((rt: any, i: number) => (
                <div key={rt.id} className="border border-border-default rounded-lg p-4 space-y-3">
                  <p className="text-xs font-bold text-accent-primary uppercase">Hasil Retesting #{i+1}</p>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <p className="text-xs text-text-muted">Tanggal</p>
                      <p className="text-xs font-bold text-text-primary">{rt.retest_date || '-'}</p>
                    </div>
                    <div>
                      <p className="text-xs text-text-muted">Status</p>
                      <p className="text-xs font-bold" style={{color: statusColor(rt.status)}}>{rt.status}</p>
                    </div>
                  </div>
                  {rt.result && <p className="text-xs text-text-primary whitespace-pre-wrap bg-bg-tertiary p-3 rounded">{rt.result}</p>}
                  {rt.evidences?.map((ev: any) => (
                    <div key={ev.id} className="space-y-1">
                      <p className="text-xs font-bold text-text-muted">{ev.label}</p>
                      {ev.url && <img src={ev.url} alt={ev.label} className="w-full max-h-48 object-contain rounded border border-border-default" />}
                    </div>
                  ))}
                </div>
              ))}

              {/* Add Retesting */}
              <div className="border border-dashed border-border-default rounded-lg p-4">
                <button onClick={() => setShowAddRetest(!showAddRetest)}
                  className="flex items-center gap-2 text-xs font-mono text-text-muted hover:text-accent-primary transition-all w-full">
                  {showAddRetest ? <ChevronUp size={12}/> : <ChevronDown size={12}/>}
                  + Tambah Hasil Retesting
                </button>
                {showAddRetest && (
                  <div className="mt-3 space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-xs font-mono text-text-muted mb-1 block">Tanggal Retesting</label>
                        <input type="date" value={newRetest.retest_date} onChange={e=>setNewRetest(p=>({...p,retest_date:e.target.value}))}
                          className="input-field font-mono text-xs w-full" />
                      </div>
                      <div>
                        <label className="text-xs font-mono text-text-muted mb-1 block">Status Retesting</label>
                        <select value={newRetest.status} onChange={e=>setNewRetest(p=>({...p,status:e.target.value}))}
                          className="input-field font-mono text-xs w-full">
                          <option value="BELUM DIPERBAIKI">BELUM DIPERBAIKI</option>
                          <option value="DIPERBAIKI">DIPERBAIKI</option>
                        </select>
                      </div>
                    </div>
                    <div>
                      <label className="text-xs font-mono text-text-muted mb-1 block">Hasil Retesting</label>
                      <textarea value={newRetest.result} onChange={e=>setNewRetest(p=>({...p,result:e.target.value}))}
                        rows={3} className="input-field font-mono text-xs w-full resize-none"
                        placeholder="Deskripsi hasil retesting..." />
                    </div>
                    <button onClick={handleAddRetest}
                      className="w-full btn-primary py-2 font-mono text-sm font-bold rounded-lg">
                      Simpan Retesting
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
