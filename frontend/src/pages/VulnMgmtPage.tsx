import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { Plus, X, Edit, Trash2, Download, Upload, Search, Filter, Settings, ChevronDown, ChevronUp, CheckCircle, Save } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import PocModal from '../components/PocModal'

// ── Constants ─────────────────────────────────────────────────
const SEV_COLOR: Record<string,string> = {
  critical:'#ff5f5f', high:'#ff9f43', medium:'#ffd43b', low:'#a9e34b', informational:'#74c7ec', info:'#74c7ec'
}
const DEFAULT_COLS = ['no','vuln_code','vuln_id','vuln_members','vuln_name','description','severity',
  'cvss_vector','cvss_score','impact','mitigation','status','finding_date','resolution_date','fixing_date','product','referensi','note']
const COL_LABELS: Record<string,string> = {
  no:'Periode', vuln_code:'Vuln Code', vuln_id:'Vuln ID', vuln_members:'Members', vuln_name:'Vuln Name',
  description:'Description', severity:'Severity', cvss_vector:'CVSS Vector', cvss_score:'CVSS Score',
  impact:'Impact', mitigation:'Mitigation', status:'Status', finding_date:'Finding Date',
  resolution_date:'Resolution Date', fixing_date:'Fixing Date', referensi:'Referensi', note:'Note', product:'Product'
}

// ── CVSS 4.0 Calculator ───────────────────────────────────────
const CVSS40_METRICS = {
  AV:  { label:'Attack Vector',       opts:['N','A','L','P'], labels:['Network','Adjacent','Local','Physical'] },
  AC:  { label:'Attack Complexity',   opts:['L','H'],         labels:['Low','High'] },
  AT:  { label:'Attack Requirements', opts:['N','P'],         labels:['None','Present'] },
  PR:  { label:'Privileges Required', opts:['N','L','H'],     labels:['None','Low','High'] },
  UI:  { label:'User Interaction',    opts:['N','P','A'],     labels:['None','Passive','Active'] },
  VC:  { label:'Conf (Vulnerable)',   opts:['H','L','N'],     labels:['High','Low','None'] },
  VI:  { label:'Integ (Vulnerable)',  opts:['H','L','N'],     labels:['High','Low','None'] },
  VA:  { label:'Avail (Vulnerable)',  opts:['H','L','N'],     labels:['High','Low','None'] },
  SC:  { label:'Conf (Subsequent)',   opts:['H','L','N'],     labels:['High','Low','None'] },
  SI:  { label:'Integ (Subsequent)',  opts:['H','L','N'],     labels:['High','Low','None'] },
  SA:  { label:'Avail (Subsequent)',  opts:['H','L','N'],     labels:['High','Low','None'] },
  E:   { label:'Exploit Maturity',    opts:['X','A','P','U'], labels:['Not Defined','Attacked','PoC','Unreported'] },
}

function calcCVSS40(vals: Record<string,string>): { score: number, rating: string, vector: string } {
  // Simplified CVSS 4.0 score calculation
  const avMap: Record<string,number> = { N:0, A:0.1, L:0.2, P:0.3 }
  const acMap: Record<string,number> = { L:0, H:0.1 }
  const atMap: Record<string,number> = { N:0, P:0.1 }
  const prMap: Record<string,number> = { N:0, L:0.1, H:0.2 }
  const uiMap: Record<string,number> = { N:0, P:0.1, A:0.2 }
  const vcMap: Record<string,number> = { H:0.5, L:0.1, N:0 }
  const viMap: Record<string,number> = { H:0.5, L:0.1, N:0 }
  const vaMap: Record<string,number> = { H:0.5, L:0.1, N:0 }
  const scMap: Record<string,number> = { H:0.3, L:0.1, N:0 }
  const siMap: Record<string,number> = { H:0.3, L:0.1, N:0 }
  const saMap: Record<string,number> = { H:0.3, L:0.1, N:0 }
  const eMap:  Record<string,number> = { X:1, A:1, P:0.94, U:0.91 }

  const exploitability = 1 - (
    (1 - (avMap[vals.AV]||0)) *
    (1 - (acMap[vals.AC]||0)) *
    (1 - (atMap[vals.AT]||0)) *
    (1 - (prMap[vals.PR]||0)) *
    (1 - (uiMap[vals.UI]||0))
  )
  const vulnImpact = 1 - (
    (1 - (vcMap[vals.VC]||0)) *
    (1 - (viMap[vals.VI]||0)) *
    (1 - (vaMap[vals.VA]||0))
  )
  const subImpact = 1 - (
    (1 - (scMap[vals.SC]||0)) *
    (1 - (siMap[vals.SI]||0)) *
    (1 - (saMap[vals.SA]||0))
  )
  const eMultiplier = eMap[vals.E] || 1
  const raw = Math.min(10, (exploitability * 5 + vulnImpact * 3 + subImpact * 2) * eMultiplier)
  const score = Math.round(raw * 10) / 10
  const rating = score === 0 ? 'None' : score < 4 ? 'Low' : score < 7 ? 'Medium' : score < 9 ? 'High' : 'Critical'
  const v = Object.entries(vals).map(([k,v]) => `${k}:${v}`).join('/')
  const vector = `CVSS:4.0/AV:${vals.AV}/AC:${vals.AC}/AT:${vals.AT}/PR:${vals.PR}/UI:${vals.UI}/VC:${vals.VC}/VI:${vals.VI}/VA:${vals.VA}/SC:${vals.SC}/SI:${vals.SI}/SA:${vals.SA}/E:${vals.E||'X'}`
  return { score, rating, vector }
}

function CVSSCalculator({ onApply, version }: { onApply: (score: number, vector: string, version: string) => void, version: string }) {
  const [cvssVer, setCvssVer] = useState<'3.1'|'4.0'>(version === '4.0' ? '4.0' : '3.1')
  const [vals40, setVals40] = useState<Record<string,string>>({
    AV:'N', AC:'L', AT:'N', PR:'N', UI:'N', VC:'H', VI:'H', VA:'H', SC:'N', SI:'N', SA:'N', E:'X'
  })
  const result40 = calcCVSS40(vals40)

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {(['3.1','4.0'] as const).map(v => (
          <button key={v} onClick={() => setCvssVer(v)}
            className={`px-3 py-1 rounded font-mono text-xs font-bold transition-all ${
              cvssVer === v ? 'bg-accent-primary bg-opacity-20 text-accent-primary border border-accent-primary border-opacity-40' : 'text-text-muted border border-border-default'
            }`}>CVSS {v}</button>
        ))}
      </div>

      {cvssVer === '4.0' && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            {Object.entries(CVSS40_METRICS).map(([key, metric]) => (
              <div key={key}>
                <label className="text-xs font-mono text-text-muted mb-1 block">{metric.label}</label>
                <div className="flex gap-1 flex-wrap">
                  {metric.opts.map((opt, i) => (
                    <button key={opt} onClick={() => setVals40(p => ({...p, [key]: opt}))}
                      className={`px-2 py-1 rounded text-xs font-mono transition-all ${
                        vals40[key] === opt
                          ? 'bg-accent-primary bg-opacity-20 text-accent-primary border border-accent-primary border-opacity-40'
                          : 'border border-border-default text-text-muted hover:text-text-primary'
                      }`} title={metric.labels[i]}>
                      {opt}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Score display */}
          <div className={`p-4 rounded-lg border text-center`}
            style={{ borderColor: SEV_COLOR[result40.rating.toLowerCase()] + '60', background: SEV_COLOR[result40.rating.toLowerCase()] + '10' }}>
            <p className="text-3xl font-mono font-bold" style={{ color: SEV_COLOR[result40.rating.toLowerCase()] || '#74c7ec' }}>
              {result40.score}
            </p>
            <p className="text-sm font-mono font-bold" style={{ color: SEV_COLOR[result40.rating.toLowerCase()] || '#74c7ec' }}>
              {result40.rating}
            </p>
            <p className="text-xs font-mono text-text-muted mt-2 break-all">{result40.vector}</p>
          </div>

          <button onClick={() => onApply(result40.score, result40.vector, '4.0')}
            className="w-full py-2 btn-primary font-mono text-sm font-bold rounded-lg">
            Apply to Vulnerability
          </button>
        </div>
      )}

      {cvssVer === '3.1' && (
        <div className="p-4 rounded-lg bg-bg-tertiary text-center">
          <p className="text-xs font-mono text-text-muted">Enter CVSS 3.1 vector manually in the form</p>
          <p className="text-xs font-mono text-text-muted mt-1">e.g. CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N</p>
        </div>
      )}
    </div>

  )
}

// ── Main Page ─────────────────────────────────────────────────
export default function VulnMgmtPage() {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)

  const [activeCompany, setActiveCompany] = useState<string|null>(null)
  const [visibleCols, setVisibleCols] = useState<string[]>(DEFAULT_COLS)
  const [search, setSearch] = useState('')
  const [filterSev, setFilterSev] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterProduct, setFilterProduct] = useState('')
  const [filterYear, setFilterYear] = useState('')
  const [showAddCompany, setShowAddCompany] = useState(false)
  const [showAddStatus, setShowAddStatus] = useState(false)
  const [showAddVuln, setShowAddVuln] = useState(false)
  const [showColFilter, setShowColFilter] = useState(false)
  const [showFilterPanel, setShowFilterPanel] = useState(false)
  const [showCVSS, setShowCVSS] = useState(false)
  const [showManageProducts, setShowManageProducts] = useState(false)
  const [newProductName, setNewProductName] = useState('')
  const [editingId, setEditingId] = useState<string|null>(null)
  const [editData, setEditData] = useState<Record<string,any>>({})
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [showBulkEdit, setShowBulkEdit] = useState(false)
  const [previewItem, setPreviewItem] = useState<any|null>(null)
  const [pocItem, setPocItem] = useState<any|null>(null)  // vuln for POC form
  const [pocData, setPocData] = useState<any|null>(null)  // existing POC data
  const [showCharts, setShowCharts] = useState(false)
  const [bulkField, setBulkField] = useState<string>('status')
  const [bulkValue, setBulkValue] = useState<string>('')
  const [newCompany, setNewCompany] = useState({ name:'', code:'', color:'#6366f1', description:'' })
  const [newStatus, setNewStatus] = useState({ name:'', color:'#74c7ec' })
  const [newVuln, setNewVuln] = useState<Record<string,any>>({
    no:'', vuln_code:'', vuln_id:'', vuln_members:'', vuln_name:'',
    description:'', severity:'medium', cvss_vector:'', cvss_score:'',
    cvss_version:'3.1', impact:'', mitigation:'', status:'Open',
    finding_date:'', resolution_date:'', fixing_date:'', referensi:'', note:''
  })

  // Queries
  const { data: companies = [] } = useQuery({ queryKey:['vuln-companies'], queryFn: () => api.get('/vuln-mgmt/companies').then(r=>r.data) })
  const { data: statuses = [] } = useQuery({ queryKey:['vuln-statuses'], queryFn: () => api.get('/vuln-mgmt/statuses').then(r=>r.data) })
  const { data: products = [] } = useQuery({
    queryKey: ['vuln-products', activeCompany],
    queryFn: () => api.get(`/vuln-mgmt/products${activeCompany ? '?company_id='+activeCompany : ''}`).then(r=>r.data),
  })
  const { data: productStats = [] } = useQuery({
    queryKey: ['vuln-product-stats'],
    queryFn: () => api.get('/vuln-mgmt/product-stats').then(r=>r.data),
  })
  const { data: stats = [] } = useQuery({ queryKey:['vuln-stats'], queryFn: () => api.get('/vuln-mgmt/stats').then(r=>r.data) })
  const { data: reports = [], isLoading } = useQuery({
    queryKey: ['vuln-reports', activeCompany, search, filterSev, filterStatus, filterProduct, filterYear],
    queryFn: () => {
      const params = new URLSearchParams()
      if (activeCompany) params.append('company_id', activeCompany)
      if (search) params.append('search', search)
      if (filterSev) params.append('severity', filterSev)
      if (filterStatus) params.append('status', filterStatus)
      if (filterProduct) params.append('product_id', filterProduct)
      if (filterYear) params.append('year', filterYear)
      return api.get(`/vuln-mgmt/reports?${params}`).then(r=>r.data)
    },
    enabled: true,
  })

  // Mutations
  const addCompany = useMutation({
    mutationFn: (d: any) => api.post('/vuln-mgmt/companies', d).then(r=>r.data),
    onSuccess: () => { qc.invalidateQueries({queryKey:['vuln-companies']}); qc.invalidateQueries({queryKey:['vuln-stats']}); setShowAddCompany(false); setNewCompany({name:'',code:'',color:'#6366f1',description:''}); toast.success('Company added') }
  })
  const delCompany = useMutation({
    mutationFn: (id: string) => api.delete(`/vuln-mgmt/companies/${id}`).then(r=>r.data),
    onSuccess: () => { qc.invalidateQueries({queryKey:['vuln-companies']}); qc.invalidateQueries({queryKey:['vuln-stats']}); if (activeCompany) setActiveCompany(null); toast.success('Company deleted') }
  })
  const addStatus = useMutation({
    mutationFn: (d: any) => api.post('/vuln-mgmt/statuses', d).then(r=>r.data),
    onSuccess: () => { qc.invalidateQueries({queryKey:['vuln-statuses']}); setShowAddStatus(false); setNewStatus({name:'',color:'#74c7ec'}); toast.success('Status added') }
  })
  const delStatus = useMutation({
    mutationFn: (id: string) => api.delete(`/vuln-mgmt/statuses/${id}`).then(r=>r.data),
    onSuccess: () => { qc.invalidateQueries({queryKey:['vuln-statuses']}); toast.success('Status deleted') }
  })
  const addProduct = useMutation({
    mutationFn: (d: any) => api.post('/vuln-mgmt/products', d).then(r=>r.data),
    onSuccess: () => { qc.invalidateQueries({queryKey:['vuln-products']}); setNewProductName(''); toast.success('Product added') }
  })
  const delProduct = useMutation({
    mutationFn: (id: string) => api.delete(`/vuln-mgmt/products/${id}`).then(r=>r.data),
    onSuccess: () => { qc.invalidateQueries({queryKey:['vuln-products']}); toast.success('Product deleted') }
  })
  const addVuln = useMutation({
    mutationFn: (d: any) => api.post('/vuln-mgmt/reports', d).then(r=>r.data),
    onSuccess: () => { qc.invalidateQueries({queryKey:['vuln-reports']}); qc.invalidateQueries({queryKey:['vuln-stats']}); qc.invalidateQueries({queryKey:['vuln-companies']}); setShowAddVuln(false); toast.success('Vulnerability added') }
  })
  const updateVuln = useMutation({
    mutationFn: ({id, data}: {id:string, data:any}) => api.put(`/vuln-mgmt/reports/${id}`, data).then(r=>r.data),
    onSuccess: () => { qc.invalidateQueries({queryKey:['vuln-reports']}); qc.invalidateQueries({queryKey:['vuln-stats']}); setEditingId(null); toast.success('Updated') }
  })
  const delVuln = useMutation({
    mutationFn: (id: string) => api.delete(`/vuln-mgmt/reports/${id}`).then(r=>r.data),
    onSuccess: () => { qc.invalidateQueries({queryKey:['vuln-reports']}); qc.invalidateQueries({queryKey:['vuln-stats']}); qc.invalidateQueries({queryKey:['vuln-companies']}); toast.success('Deleted') }
  })

  const bulkUpdate = useMutation({
    mutationFn: async ({ids, field, value}: {ids: string[], field: string, value: string}) => {
      await Promise.all(ids.map(id => api.put(`/vuln-mgmt/reports/${id}`, {[field]: value})))
    },
    onSuccess: () => {
      qc.invalidateQueries({queryKey:['vuln-reports']})
      qc.invalidateQueries({queryKey:['vuln-stats']})
      setSelectedIds(new Set())
      setShowBulkEdit(false)
      setBulkValue('')
      toast.success(`Updated ${selectedIds.size} vulnerabilities`)
    }
  })

  const activeComp = companies.find((c:any) => c.id === activeCompany)
  const allStatuses = ['Open','On Progress','Fixed/Closed','Revamp', ...statuses.filter((s:any)=>!s.is_default).map((s:any)=>s.name)]
  const statusColors: Record<string,string> = {
    'Open': '#ff5f5f', 'On Progress': '#ffd43b', 'Fixed/Closed': '#a9e34b', 'Revamp': '#74c7ec',
    ...Object.fromEntries(statuses.map((s:any) => [s.name, s.color]))
  }

  const startEdit = (r: any) => { setEditingId(r.id); setEditData({...r}) }
  const toggleSelect = (id: string) => setSelectedIds(prev => {
    const next = new Set(prev)
    next.has(id) ? next.delete(id) : next.add(id)
    return next
  })
  const toggleSelectAll = () => {
    if (selectedIds.size === reports.length) setSelectedIds(new Set())
    else setSelectedIds(new Set(reports.map((r:any) => r.id)))
  }
  const saveEdit = () => updateVuln.mutate({ id: editingId!, data: editData })

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !activeCompany) return
    const fd = new FormData()
    fd.append('file', file)
    try {
      const res = await api.post(`/vuln-mgmt/reports/import?company_id=${activeCompany}`, fd, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      toast.success(`Imported ${res.data.imported} vulnerabilities`)
      qc.invalidateQueries({queryKey:['vuln-reports']})
      qc.invalidateQueries({queryKey:['vuln-companies']})
      qc.invalidateQueries({queryKey:['vuln-stats']})
    } catch(e: any) {
      toast.error(e.response?.data?.detail || 'Import failed')
    }
    e.target.value = ''
  }

  const handleExport = () => {
    if (!activeCompany) return
    const authRaw = localStorage.getItem('offensecops-auth')
    const token = authRaw ? JSON.parse(authRaw)?.state?.accessToken : ''
    window.open(`/api/vuln-mgmt/reports/export?company_id=${activeCompany}&token=${token}`)
  }

  return (
    <div className="h-full flex flex-col gap-3 p-4 overflow-y-auto min-h-0">
      {/* Header */}
      <div className="flex items-center justify-between flex-shrink-0">
        <div>
          <h1 className="text-xl font-mono font-bold text-text-primary">Vulnerability Management</h1>
          <p className="text-xs font-mono text-text-muted mt-0.5">Multi-company vulnerability tracking & reporting</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowManageProducts(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border border-border-default text-text-muted hover:text-accent-primary hover:border-accent-primary transition-all">
            <Settings size={12} /> Products
          </button>
          <button onClick={() => setShowAddStatus(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border border-border-default text-text-muted hover:text-accent-primary hover:border-accent-primary transition-all">
            <Settings size={12} /> Manage Status
          </button>
          <button onClick={() => setShowAddCompany(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono btn-primary">
            <Plus size={12} /> Add Company
          </button>
        </div>
      </div>

      {/* Charts toggle button */}
      <div className="flex-shrink-0">
        <button onClick={() => setShowCharts(!showCharts)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono border border-border-default text-text-muted hover:text-accent-primary hover:border-accent-primary transition-all">
          {showCharts ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          {showCharts ? 'Hide Charts' : 'Show Charts'}
        </button>
      </div>

      {showCharts && <div className="flex flex-col gap-3 flex-shrink-0">
      {/* Charts Section */}
      <div className="grid grid-cols-3 gap-4 flex-shrink-0">
        {stats.map((s: any) => {
          const statusData = Object.entries(s.by_status).map(([name, val]) => ({
            name, value: val as number, color: statusColors[name] || '#74c7ec'
          }))
          const total = statusData.reduce((a,b) => a + b.value, 0)
          return (
            <div key={s.company.id} className={`card p-4 cursor-pointer transition-all ${activeCompany === s.company.id ? 'border-accent-primary' : ''}`}
              onClick={() => setActiveCompany(activeCompany === s.company.id ? null : s.company.id)}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{background: s.company.color}} />
                  <p className="text-sm font-mono font-bold text-text-primary">{s.company.name}</p>
                </div>
                <span className="text-xs font-mono text-text-muted">{total} vulns</span>
              </div>
              {total > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={90}>
                    <PieChart>
                      <Pie data={statusData} cx="50%" cy="50%" innerRadius={22} outerRadius={38} dataKey="value" paddingAngle={2}>
                        {statusData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                      </Pie>
                      <Tooltip contentStyle={{background:'#1e1e2e',border:'1px solid #313244',fontSize:'11px',fontFamily:'monospace'}}
                        formatter={(v: any, n: any) => [v, n]} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="space-y-1 mt-2">
                    {statusData.map(d => (
                      <div key={d.name} className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5">
                          <div className="w-2 h-2 rounded-full flex-shrink-0" style={{background:d.color}} />
                          <span className="text-xs font-mono text-text-muted">{d.name}</span>
                        </div>
                        <span className="text-xs font-mono font-bold text-text-primary">{d.value}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="h-24 flex items-center justify-center">
                  <p className="text-xs font-mono text-text-muted opacity-50">No data</p>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Severity bar chart across all */}
      {stats.length > 0 && (
        <div className="card p-4 flex-shrink-0">
          <p className="text-xs font-mono font-bold text-text-muted mb-3">Severity Distribution by Company</p>
          <ResponsiveContainer width="100%" height={90}>
            <BarChart data={['critical','high','medium','low','informational'].map(sev => ({
              sev: sev.charAt(0).toUpperCase() + sev.slice(1),
              ...Object.fromEntries(stats.map((s:any) => [s.company.code, s.by_severity[sev] || 0]))
            }))}>
              <XAxis dataKey="sev" tick={{fontSize:10, fontFamily:'monospace'}} />
              <YAxis tick={{fontSize:10, fontFamily:'monospace'}} />
              <Tooltip contentStyle={{background:'#1e1e2e',border:'1px solid #313244',fontSize:'11px',fontFamily:'monospace'}} />
              <Legend wrapperStyle={{fontSize:'11px', fontFamily:'monospace'}} />
              {stats.map((s:any) => <Bar key={s.company.id} dataKey={s.company.code} fill={s.company.color} radius={[2,2,0,0]} />)}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Product donut charts per company */}
      {productStats.length > 0 && (
        <div className="space-y-2 flex-shrink-0">
          <p className="text-xs font-mono font-bold text-text-muted">Vulnerabilities by Product</p>
          <div className="grid grid-cols-3 gap-4">
            {productStats.map((cs: any) => {
              const comp = companies.find((c:any) => c.id === cs.company_id)
              if (!cs.products || cs.products.length === 0) return null
              const COLORS = ['#6366f1','#06b6d4','#a9e34b','#ff9f43','#ff5f5f','#74c7ec','#ffd43b','#ff79c6','#bd93f9']
              return (
                <div key={cs.company_id} className={`card p-4 cursor-pointer transition-all ${activeCompany === cs.company_id ? 'border-accent-primary' : ''}`}
                  onClick={() => setActiveCompany(activeCompany === cs.company_id ? null : cs.company_id)}>
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-3 h-3 rounded-full flex-shrink-0" style={{background: comp?.color || '#6366f1'}} />
                    <p className="text-xs font-mono font-bold text-text-primary">{comp?.name} — Products</p>
                  </div>
                  <div className="flex gap-3">
                    <ResponsiveContainer width={100} height={100}>
                      <PieChart>
                        <Pie data={cs.products} cx="50%" cy="50%" innerRadius={25} outerRadius={45}
                          dataKey="count" paddingAngle={2}>
                          {cs.products.map((_: any, i: number) => (
                            <Cell key={i} fill={COLORS[i % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{background:'#1e1e2e',border:'1px solid #313244',fontSize:'10px',fontFamily:'monospace'}}
                          formatter={(v:any, _:any, props:any) => [v, props.payload.name]} />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="flex-1 space-y-1 min-w-0 overflow-y-auto max-h-24">
                      {cs.products.map((p: any, i: number) => (
                        <div key={p.name} className="flex items-center justify-between gap-1">
                          <div className="flex items-center gap-1 min-w-0">
                            <div className="w-2 h-2 rounded-full flex-shrink-0" style={{background: COLORS[i % COLORS.length]}} />
                            <span className="text-xs font-mono text-text-muted truncate">{p.name}</span>
                          </div>
                          <span className="text-xs font-mono font-bold text-text-primary flex-shrink-0">{p.count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      </div>}

      {/* Company tabs */}
      <div className="flex gap-2 flex-shrink-0 flex-wrap">
        <button onClick={() => setActiveCompany(null)}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${!activeCompany ? 'bg-accent-primary bg-opacity-20 text-accent-primary border border-accent-primary border-opacity-40' : 'text-text-muted border border-border-default hover:text-text-primary'}`}>
          All Companies
        </button>
        {companies.map((c:any) => (
          <button key={c.id} onClick={() => setActiveCompany(c.id)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all flex items-center gap-1.5 ${activeCompany === c.id ? 'border' : 'border border-border-default text-text-muted hover:text-text-primary'}`}
            style={activeCompany === c.id ? {borderColor:c.color+'60', background:c.color+'15', color:c.color} : {}}>
            <div className="w-2 h-2 rounded-full" style={{background:c.color}} />
            {c.code} ({c.total})
          </button>
        ))}
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-shrink-0 flex-wrap">
        {/* Search */}
        <div className="relative flex-1 min-w-48">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search vulnerabilities..."
            className="input-field pl-7 text-xs font-mono w-full" />
        </div>
        {/* Filter button + panel */}
        <div className="relative">
          <button onClick={() => setShowFilterPanel(!showFilterPanel)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all ${
              (filterSev||filterStatus||filterProduct||filterYear)
                ? 'border-accent-primary text-accent-primary bg-accent-primary bg-opacity-10'
                : 'border-border-default text-text-muted hover:text-accent-primary'
            }`}>
            <Filter size={12} />
            Filter
            {(filterSev||filterStatus||filterProduct||filterYear) && (
              <span className="bg-accent-primary text-white rounded-full w-4 h-4 flex items-center justify-center text-xs font-bold">
                {[filterSev,filterStatus,filterProduct,filterYear].filter(Boolean).length}
              </span>
            )}
          </button>
          {showFilterPanel && (
            <div className="absolute left-0 top-9 z-50 card p-4 w-64 space-y-3 shadow-xl"
              onClick={e => e.stopPropagation()}>
              <div className="flex items-center justify-between">
                <p className="text-xs font-mono font-bold text-text-primary">Filters</p>
                <button onClick={() => { setFilterSev(''); setFilterStatus(''); setFilterProduct(''); setFilterYear('') }}
                  className="text-xs font-mono text-text-muted hover:text-severity-critical transition-colors">
                  Reset All
                </button>
              </div>
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">Severity</label>
                <select value={filterSev} onChange={e=>setFilterSev(e.target.value)}
                  className="input-field text-xs font-mono w-full">
                  <option value="">All Severity</option>
                  {['critical','high','medium','low','informational'].map(s => (
                    <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">Status</label>
                <select value={filterStatus} onChange={e=>setFilterStatus(e.target.value)}
                  className="input-field text-xs font-mono w-full">
                  <option value="">All Status</option>
                  {allStatuses.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">Product</label>
                <select value={filterProduct} onChange={e=>setFilterProduct(e.target.value)}
                  className="input-field text-xs font-mono w-full">
                  <option value="">All Products</option>
                  {products.filter((p:any) => !activeCompany || p.company_id === activeCompany).map((p:any) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">Periode</label>
                <select value={filterYear} onChange={e=>setFilterYear(e.target.value)}
                  className="input-field text-xs font-mono w-full">
                  <option value="">All Periode</option>
                  {[2023,2024,2025,2026,2027].map(y => (
                    <option key={y} value={String(y)}>{y}</option>
                  ))}
                </select>
              </div>
              <button onClick={() => setShowFilterPanel(false)}
                className="w-full py-1.5 btn-primary rounded-lg text-xs font-mono font-bold">
                Apply
              </button>
            </div>
          )}
        </div>
        {/* Column filter */}
        <div className="relative">
          <button onClick={() => setShowColFilter(!showColFilter)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border border-border-default text-text-muted hover:text-accent-primary transition-all">
            <Filter size={12} /> Columns ({visibleCols.length}/{DEFAULT_COLS.length})
          </button>
          {showColFilter && (
            <div className="absolute right-0 top-8 z-50 card p-3 w-48 space-y-1 max-h-64 overflow-y-auto">
              {DEFAULT_COLS.map(col => (
                <label key={col} className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={visibleCols.includes(col)}
                    onChange={() => setVisibleCols(prev => prev.includes(col) ? prev.filter(c=>c!==col) : [...prev,col])}
                    className="w-3 h-3" />
                  <span className="text-xs font-mono text-text-muted">{COL_LABELS[col]}</span>
                </label>
              ))}
            </div>
          )}
        </div>
        {activeCompany && <>
          <button onClick={() => setShowCVSS(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border border-border-default text-text-muted hover:text-accent-primary transition-all">
            CVSS Calc
          </button>
          <input ref={fileRef} type="file" accept=".xlsx,.xls" className="hidden" onChange={handleImport} />
          <button onClick={() => fileRef.current?.click()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border border-border-default text-text-muted hover:text-accent-primary transition-all">
            <Upload size={12} /> Import
          </button>
          <button onClick={handleExport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border border-border-default text-text-muted hover:text-accent-primary transition-all">
            <Download size={12} /> Export
          </button>
          <button onClick={() => { setShowAddVuln(true); setNewVuln(p=>({...p,company_id:activeCompany,status:'Open'})) }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono btn-primary">
            <Plus size={12} /> Add Vuln
          </button>
        </>}
      </div>

      {/* Bulk edit bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-accent-primary bg-opacity-10 border border-accent-primary border-opacity-30 flex-shrink-0">
          <span className="text-xs font-mono text-accent-primary font-bold">{selectedIds.size} selected</span>
          <button onClick={() => setShowBulkEdit(true)}
            className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono bg-accent-primary bg-opacity-20 text-accent-primary hover:bg-opacity-30 transition-all">
            <Edit size={11} /> Bulk Edit
          </button>
          <button onClick={() => {
            if (confirm(`Delete ${selectedIds.size} vulnerabilities?`)) {
              Promise.all([...selectedIds].map(id => api.delete(`/vuln-mgmt/reports/${id}`))).then(() => {
                qc.invalidateQueries({queryKey:['vuln-reports']})
                qc.invalidateQueries({queryKey:['vuln-stats']})
                qc.invalidateQueries({queryKey:['vuln-companies']})
                setSelectedIds(new Set())
                toast.success('Deleted')
              })
            }
          }} className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono bg-severity-critical bg-opacity-10 text-severity-critical hover:bg-opacity-20 transition-all">
            <Trash2 size={11} /> Delete Selected
          </button>
          <button onClick={() => setSelectedIds(new Set())} className="ml-auto text-text-muted hover:text-text-primary transition-colors">
            <X size={13} />
          </button>
        </div>
      )}

      {/* Table */}
      <div className="card overflow-auto" style={{minHeight:'300px', maxHeight:'calc(100vh - 280px)', flex:'1 1 300px'}}>
        <table className="w-full text-xs font-mono border-collapse min-w-max">
          <thead className="sticky top-0 z-10 bg-bg-secondary">
            <tr>
              <th className="px-3 py-2 border-b border-border-default w-8">
                <input type="checkbox"
                  checked={reports.length > 0 && selectedIds.size === reports.length}
                  onChange={toggleSelectAll}
                  className="w-3 h-3 cursor-pointer" />
              </th>
              {visibleCols.map(col => (
                <th key={col} className="text-left px-3 py-2 text-text-muted border-b border-border-default whitespace-nowrap font-bold">
                  {COL_LABELS[col]}
                </th>
              ))}
              <th className="px-3 py-2 text-text-muted border-b border-border-default text-center">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={visibleCols.length+1} className="text-center py-8 text-text-muted">Loading...</td></tr>
            ) : reports.length === 0 ? (
              <tr><td colSpan={visibleCols.length+1} className="text-center py-8 text-text-muted">
                {activeCompany ? 'No vulnerabilities found — add one or import Excel' : 'Select a company to view vulnerabilities'}
              </td></tr>
            ) : reports.map((r: any) => (
              <tr key={r.id} onClick={() => !editingId && setPreviewItem(r)}
                className={`border-b border-border-default hover:bg-bg-tertiary transition-colors cursor-pointer ${selectedIds.has(r.id) ? 'bg-accent-primary bg-opacity-5' : ''}`}>
                <td className="px-3 py-2" onClick={e => e.stopPropagation()}>
                  <input type="checkbox" checked={selectedIds.has(r.id)} onChange={() => toggleSelect(r.id)}
                    className="w-3 h-3 cursor-pointer" />
                </td>
                {visibleCols.map(col => (
                  <td key={col} className="px-3 py-2 max-w-xs">
                    {editingId === r.id ? (
                      col === 'severity' ? (
                        <select value={editData[col]||''} onChange={e=>setEditData(p=>({...p,[col]:e.target.value}))}
                          className="input-field text-xs w-full">
                          {['critical','high','medium','low','informational'].map(s=><option key={s} value={s}>{s}</option>)}
                        </select>
                      ) : col === 'status' ? (
                        <select value={editData[col]||''} onChange={e=>setEditData(p=>({...p,[col]:e.target.value}))}
                          className="input-field text-xs w-full">
                          {allStatuses.map(s=><option key={s} value={s}>{s}</option>)}
                        </select>
                      ) : col === 'product' ? (
                        <select value={editData['product_id']||''} onChange={e=>setEditData(p=>({...p,product_id:e.target.value}))}
                          className="input-field text-xs w-full">
                          <option value="">None</option>
                          {products.filter((p:any) => p.company_id === (editData.company_id || activeCompany)).map((p:any) => (
                            <option key={p.id} value={p.id}>{p.name}</option>
                          ))}
                        </select>
                      ) : (
                        <input value={editData[col]||''} onChange={e=>setEditData(p=>({...p,[col]:e.target.value}))}
                          className="input-field text-xs w-full min-w-24" />
                      )
                    ) : (
                      col === 'severity' ? (
                        <span className="px-1.5 py-0.5 rounded text-xs font-bold"
                          style={{background:(SEV_COLOR[r.severity]||'#74c7ec')+'20', color:SEV_COLOR[r.severity]||'#74c7ec'}}>
                          {r.severity}
                        </span>
                      ) : col === 'status' ? (
                        <span className="px-1.5 py-0.5 rounded text-xs font-bold"
                          style={{background:(statusColors[r.status]||'#74c7ec')+'20', color:statusColors[r.status]||'#74c7ec'}}>
                          {r.status}
                        </span>
                      ) : col === 'product' ? (
                        <span className={!r.product_id ? 'text-text-muted opacity-40' : 'text-accent-primary'}>
                          {products.find((p:any) => p.id === r.product_id)?.name || '-'}
                        </span>
                      ) : col === 'cvss_score' ? (
                        <span className={r.cvss_score ? 'font-bold' : 'text-text-muted opacity-40'}>
                          {r.cvss_score || '-'}
                        </span>
                      ) : (
                        <span className={`${['description','impact','mitigation','note','referensi','vuln_name'].includes(col)
                            ? 'block max-w-xs break-words whitespace-pre-wrap line-clamp-2'
                            : 'whitespace-nowrap'} ${!r[col] ? 'text-text-muted opacity-40' : ''}`}>
                          {r[col] || '-'}
                        </span>
                      )
                    )}
                  </td>
                ))}
                <td className="px-3 py-2" onClick={e => e.stopPropagation()}>
                  <div className="flex items-center gap-1 justify-center">
                    {editingId === r.id ? (
                      <>
                        <button onClick={saveEdit} className="p-1 text-severity-low hover:text-severity-low transition-colors" title="Save">
                          <Save size={13} />
                        </button>
                        <button onClick={() => setEditingId(null)} className="p-1 text-text-muted hover:text-text-primary transition-colors" title="Cancel">
                          <X size={13} />
                        </button>
                      </>
                    ) : (
                      <>
                        <button onClick={(e) => { e.stopPropagation(); startEdit(r) }} className="p-1 text-text-muted hover:text-accent-primary transition-colors" title="Edit">
                          <Edit size={13} />
                        </button>
                        <button onClick={async (e) => {
                          e.stopPropagation()
                          try {
                            const authRaw = localStorage.getItem('offensecops-auth')
                            const token = authRaw ? JSON.parse(authRaw)?.state?.accessToken : ''
                            const res = await fetch(`/api/poc?vuln_report_id=${r.id}`, {headers:{Authorization:`Bearer ${token}`}})
                            const pocs = await res.json()
                            setPocData(pocs)
                            setPocItem(r)
                          } catch(err) {
                            setPocData([])
                            setPocItem(r)
                          }
                        }} className="p-1 text-text-muted hover:text-severity-medium transition-colors" title="POC">
                          <span className="text-xs font-bold font-mono" style={{color:'#ffd43b'}}>POC</span>
                        </button>
                        <button onClick={(e) => { e.stopPropagation(); if(confirm('Delete?')) delVuln.mutate(r.id) }} className="p-1 text-text-muted hover:text-severity-critical transition-colors" title="Delete">
                          <Trash2 size={13} />
                        </button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Modals ── */}

      {/* Add Company */}
      {showAddCompany && (
        <div className="fixed inset-0 bg-black bg-opacity-60 z-50 flex items-center justify-center p-4">
          <div className="card p-6 w-full max-w-md space-y-4">
            <div className="flex items-center justify-between">
              <p className="font-mono font-bold text-text-primary">Add Company</p>
              <button onClick={() => setShowAddCompany(false)}><X size={16} className="text-text-muted" /></button>
            </div>
            {[
              {key:'name', label:'Company Name', ph:'PT Sprint Asia Technology'},
              {key:'code', label:'Code', ph:'SPRINT'},
              {key:'description', label:'Description', ph:'Optional'},
            ].map(f => (
              <div key={f.key}>
                <label className="text-xs font-mono text-text-muted mb-1 block">{f.label}</label>
                <input value={newCompany[f.key as keyof typeof newCompany]} onChange={e=>setNewCompany(p=>({...p,[f.key]:e.target.value}))}
                  placeholder={f.ph} className="input-field font-mono text-sm w-full" />
              </div>
            ))}
            <div>
              <label className="text-xs font-mono text-text-muted mb-1 block">Color</label>
              <input type="color" value={newCompany.color} onChange={e=>setNewCompany(p=>({...p,color:e.target.value}))}
                className="w-full h-10 rounded-lg border border-border-default cursor-pointer" />
            </div>
            <button onClick={() => addCompany.mutate(newCompany)} disabled={!newCompany.name || !newCompany.code}
              className="w-full btn-primary py-2 font-mono font-bold rounded-lg disabled:opacity-50">
              Add Company
            </button>
          </div>
        </div>
      )}

      {/* Manage Status */}
      {showAddStatus && (
        <div className="fixed inset-0 bg-black bg-opacity-60 z-50 flex items-center justify-center p-4">
          <div className="card p-6 w-full max-w-md space-y-4">
            <div className="flex items-center justify-between">
              <p className="font-mono font-bold text-text-primary">Manage Statuses</p>
              <button onClick={() => setShowAddStatus(false)}><X size={16} className="text-text-muted" /></button>
            </div>
            {/* Existing statuses */}
            <div className="space-y-2">
              {statuses.map((s:any) => (
                <div key={s.id} className="flex items-center gap-2 p-2 rounded-lg bg-bg-tertiary">
                  <div className="w-3 h-3 rounded-full flex-shrink-0" style={{background:s.color}} />
                  <span className="text-xs font-mono text-text-primary flex-1">{s.name}</span>
                  {!s.is_default && (
                    <button onClick={() => delStatus.mutate(s.id)} className="text-text-muted hover:text-severity-critical transition-colors">
                      <Trash2 size={12} />
                    </button>
                  )}
                </div>
              ))}
            </div>
            {/* Add new status */}
            <div className="border-t border-border-default pt-3 space-y-2">
              <p className="text-xs font-mono text-text-muted font-bold">Add Custom Status</p>
              <input value={newStatus.name} onChange={e=>setNewStatus(p=>({...p,name:e.target.value}))}
                placeholder="Status name" className="input-field font-mono text-sm w-full" />
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">Color</label>
                <input type="color" value={newStatus.color} onChange={e=>setNewStatus(p=>({...p,color:e.target.value}))}
                  className="w-full h-8 rounded border border-border-default cursor-pointer" />
              </div>
              <button onClick={() => addStatus.mutate(newStatus)} disabled={!newStatus.name}
                className="w-full btn-primary py-1.5 font-mono text-sm font-bold rounded-lg disabled:opacity-50">
                Add Status
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Vulnerability */}
      {showAddVuln && (
        <div className="fixed inset-0 bg-black bg-opacity-60 z-50 flex items-center justify-center p-4">
          <div className="card p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto space-y-4">
            <div className="flex items-center justify-between">
              <p className="font-mono font-bold text-text-primary">Add Vulnerability</p>
              <button onClick={() => setShowAddVuln(false)}><X size={16} className="text-text-muted" /></button>
            </div>
            <div className="grid grid-cols-2 gap-3">
              {[
                {key:'no', label:'Periode', ph:'2025'},
                {key:'vuln_code', label:'Vuln Code', ph:'SP-A05'},
                {key:'vuln_id', label:'Vuln ID', ph:'SP-A05-01'},
                {key:'vuln_members', label:'Members', ph:'Security Team'},
                {key:'vuln_name', label:'Vuln Name *', ph:'Multiple Security Header Vulnerability'},
                {key:'cvss_vector', label:'CVSS Vector', ph:'CVSS:3.1/AV:N/AC:H/...'},
                {key:'finding_date', label:'Finding Date', ph:'2025-04-18'},
                {key:'resolution_date', label:'Resolution Date', ph:'2025-05-01'},
                {key:'fixing_date', label:'Fixing Date', ph:'2025-05-15'},
              ].map(f => (
                <div key={f.key}>
                  <label className="text-xs font-mono text-text-muted mb-1 block">{f.label}</label>
                  <input value={newVuln[f.key]||''} onChange={e=>setNewVuln(p=>({...p,[f.key]:e.target.value}))}
                    placeholder={f.ph} className="input-field font-mono text-xs w-full" />
                </div>
              ))}
              {/* CVSS Score + Calculator */}
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">CVSS Score</label>
                <div className="flex gap-2">
                  <input value={newVuln.cvss_score||''} onChange={e=>setNewVuln((p:any)=>({...p,cvss_score:e.target.value}))}
                    placeholder="4.8" className="input-field font-mono text-xs flex-1" />
                  <button type="button" onClick={() => { setShowAddVuln(false); setShowCVSS(true) }}
                    className="px-2 py-1 rounded border border-accent-primary text-accent-primary text-xs font-mono hover:bg-accent-primary hover:bg-opacity-10 transition-all whitespace-nowrap flex-shrink-0">
                    🧮 Calc
                  </button>
                </div>
              </div>
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">Severity</label>
                <select value={newVuln.severity} onChange={e=>setNewVuln(p=>({...p,severity:e.target.value}))}
                  className="input-field font-mono text-xs w-full">
                  {['critical','high','medium','low','informational'].map(s=><option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs font-mono text-text-muted mb-1 block">Status</label>
                <select value={newVuln.status} onChange={e=>setNewVuln(p=>({...p,status:e.target.value}))}
                  className="input-field font-mono text-xs w-full">
                  {allStatuses.map(s=><option key={s} value={s}>{s}</option>)}
                </select>
              </div>
            </div>
            <div className="col-span-2">
              <label className="text-xs font-mono text-text-muted mb-1 block">Product</label>
              <div className="flex gap-2">
                <select value={newVuln.product_id||''} onChange={e=>setNewVuln((p:any)=>({...p,product_id:e.target.value}))}
                  className="input-field font-mono text-xs flex-1">
                  <option value="">-- Select Product --</option>
                  {products.filter((p:any) => p.company_id === activeCompany).map((p:any) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </div>
            </div>
            {[
              {key:'description', label:'Description'},
              {key:'impact', label:'Impact'},
              {key:'mitigation', label:'Mitigation'},
              {key:'referensi', label:'Referensi'},
              {key:'note', label:'Note'},
            ].map(f => (
              <div key={f.key}>
                <label className="text-xs font-mono text-text-muted mb-1 block">{f.label}</label>
                <textarea value={newVuln[f.key]||''} onChange={e=>setNewVuln(p=>({...p,[f.key]:e.target.value}))}
                  rows={2} className="input-field font-mono text-xs w-full resize-none" />
              </div>
            ))}
            <button onClick={() => addVuln.mutate({...newVuln, company_id: activeCompany})}
              disabled={!newVuln.vuln_name || !activeCompany}  
              className="w-full btn-primary py-2 font-mono font-bold rounded-lg disabled:opacity-50">
              Add Vulnerability
            </button>
          </div>
        </div>
      )}

      {/* Manage Products */}
      {showManageProducts && (
        <div className="fixed inset-0 bg-black bg-opacity-60 z-50 flex items-center justify-center p-4">
          <div className="card p-6 w-full max-w-md space-y-4">
            <div className="flex items-center justify-between">
              <p className="font-mono font-bold text-text-primary">
                Manage Products {activeCompany ? `— ${companies.find((c:any)=>c.id===activeCompany)?.code}` : '(All)'}
              </p>
              <button onClick={() => setShowManageProducts(false)}><X size={16} className="text-text-muted" /></button>
            </div>
            {/* Products list */}
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {products.length === 0 && <p className="text-xs font-mono text-text-muted text-center py-4">No products</p>}
              {products.map((p:any) => {
                const comp = companies.find((c:any) => c.id === p.company_id)
                return (
                  <div key={p.id} className="flex items-center gap-2 p-2 rounded-lg bg-bg-tertiary">
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{background: comp?.color || '#74c7ec'}} />
                    <span className="text-xs font-mono text-text-muted flex-shrink-0">{comp?.code}</span>
                    <span className="text-xs font-mono text-text-primary flex-1">{p.name}</span>
                    <button onClick={() => delProduct.mutate(p.id)} className="text-text-muted hover:text-severity-critical transition-colors">
                      <Trash2 size={12} />
                    </button>
                  </div>
                )
              })}
            </div>
            {/* Add new product */}
            <div className="border-t border-border-default pt-3 space-y-2">
              <p className="text-xs font-mono text-text-muted font-bold">Add Product</p>
              <select className="input-field font-mono text-xs w-full"
                onChange={e => setActiveCompany(e.target.value)}
                value={activeCompany || ''}>
                <option value="">Select Company</option>
                {companies.map((c:any) => <option key={c.id} value={c.id}>{c.name} ({c.code})</option>)}
              </select>
              <input value={newProductName} onChange={e=>setNewProductName(e.target.value)}
                placeholder="Product name" className="input-field font-mono text-sm w-full" />
              <button onClick={() => addProduct.mutate({company_id: activeCompany, name: newProductName})}
                disabled={!newProductName || !activeCompany}
                className="w-full btn-primary py-1.5 font-mono text-sm font-bold rounded-lg disabled:opacity-50">
                Add Product
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {previewItem && (
        <div className="fixed inset-0 bg-black bg-opacity-60 z-50 flex items-center justify-center p-4"
          onClick={() => setPreviewItem(null)}>
          <div className="card w-full max-w-3xl max-h-[90vh] overflow-y-auto"
            onClick={e => e.stopPropagation()}>
            {/* Header */}
            <div className="flex items-start justify-between p-5 border-b border-border-default">
              <div className="flex-1 min-w-0 pr-4">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  {previewItem.vuln_id && <span className="text-xs font-mono text-accent-primary font-bold">{previewItem.vuln_id}</span>}
                  {previewItem.vuln_code && <span className="text-xs font-mono text-text-muted">{previewItem.vuln_code}</span>}
                  {previewItem.no && <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-bg-tertiary text-text-muted">Periode: {previewItem.no}</span>}
                </div>
                <h2 className="text-base font-mono font-bold text-text-primary">{previewItem.vuln_name}</h2>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold"
                    style={{background:(SEV_COLOR[previewItem.severity]||'#74c7ec')+'20', color:SEV_COLOR[previewItem.severity]||'#74c7ec'}}>
                    {previewItem.severity?.toUpperCase()}
                  </span>
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold"
                    style={{background:(statusColors[previewItem.status]||'#74c7ec')+'20', color:statusColors[previewItem.status]||'#74c7ec'}}>
                    {previewItem.status}
                  </span>
                  {previewItem.cvss_score && (
                    <span className="px-2 py-0.5 rounded text-xs font-mono bg-bg-tertiary text-text-muted">
                      CVSS {previewItem.cvss_version}: {previewItem.cvss_score}
                    </span>
                  )}
                  {products.find((p:any) => p.id === previewItem.product_id) && (
                    <span className="px-2 py-0.5 rounded text-xs font-mono bg-accent-primary bg-opacity-10 text-accent-primary">
                      {products.find((p:any) => p.id === previewItem.product_id)?.name}
                    </span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <button onClick={() => { setPreviewItem(null); startEdit(previewItem) }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border border-border-default text-text-muted hover:text-accent-primary hover:border-accent-primary transition-all">
                  <Edit size={12} /> Edit
                </button>
                <button onClick={() => setPreviewItem(null)}>
                  <X size={16} className="text-text-muted hover:text-text-primary transition-colors" />
                </button>
              </div>
            </div>

            {/* Body */}
            <div className="p-5 space-y-4">
              {/* Dates row */}
              <div className="grid grid-cols-3 gap-3">
                {[
                  {label:'Finding Date', val: previewItem.finding_date},
                  {label:'Resolution Date', val: previewItem.resolution_date},
                  {label:'Fixing Date', val: previewItem.fixing_date},
                ].map(d => (
                  <div key={d.label} className="p-2 rounded-lg bg-bg-tertiary">
                    <p className="text-xs font-mono text-text-muted mb-0.5">{d.label}</p>
                    <p className="text-xs font-mono text-text-primary font-bold">{d.val || '—'}</p>
                  </div>
                ))}
              </div>

              {/* CVSS Vector */}
              {previewItem.cvss_vector && (
                <div>
                  <p className="text-xs font-mono text-text-muted mb-1 font-bold">CVSS Vector</p>
                  <p className="text-xs font-mono text-accent-primary bg-bg-tertiary px-3 py-2 rounded-lg break-all">{previewItem.cvss_vector}</p>
                </div>
              )}

              {/* Members */}
              {previewItem.vuln_members && (
                <div>
                  <p className="text-xs font-mono text-text-muted mb-1 font-bold">Members</p>
                  <p className="text-xs font-mono text-text-primary">{previewItem.vuln_members}</p>
                </div>
              )}

              {/* Description */}
              {previewItem.description && (
                <div>
                  <p className="text-xs font-mono text-text-muted mb-1 font-bold">Description</p>
                  <p className="text-xs font-mono text-text-primary leading-relaxed whitespace-pre-wrap bg-bg-tertiary px-3 py-2 rounded-lg">{previewItem.description}</p>
                </div>
              )}

              {/* Impact */}
              {previewItem.impact && (
                <div>
                  <p className="text-xs font-mono text-text-muted mb-1 font-bold">Impact</p>
                  <p className="text-xs font-mono text-text-primary leading-relaxed whitespace-pre-wrap bg-bg-tertiary px-3 py-2 rounded-lg">{previewItem.impact}</p>
                </div>
              )}

              {/* Mitigation */}
              {previewItem.mitigation && (
                <div>
                  <p className="text-xs font-mono text-text-muted mb-1 font-bold">Mitigation</p>
                  <p className="text-xs font-mono text-text-primary leading-relaxed whitespace-pre-wrap bg-bg-tertiary px-3 py-2 rounded-lg">{previewItem.mitigation}</p>
                </div>
              )}

              {/* Referensi */}
              {previewItem.referensi && (
                <div>
                  <p className="text-xs font-mono text-text-muted mb-1 font-bold">Referensi</p>
                  <p className="text-xs font-mono text-text-primary leading-relaxed whitespace-pre-wrap bg-bg-tertiary px-3 py-2 rounded-lg">{previewItem.referensi}</p>
                </div>
              )}

              {/* Note */}
              {previewItem.note && (
                <div>
                  <p className="text-xs font-mono text-text-muted mb-1 font-bold">Note</p>
                  <p className="text-xs font-mono text-text-primary leading-relaxed whitespace-pre-wrap bg-bg-tertiary px-3 py-2 rounded-lg">{previewItem.note}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Bulk Edit Modal */}
      {showBulkEdit && (
        <div className="fixed inset-0 bg-black bg-opacity-60 z-50 flex items-center justify-center p-4">
          <div className="card p-6 w-full max-w-md space-y-4">
            <div className="flex items-center justify-between">
              <p className="font-mono font-bold text-text-primary">
                Bulk Edit — {selectedIds.size} vulnerabilities
              </p>
              <button onClick={() => setShowBulkEdit(false)}><X size={16} className="text-text-muted" /></button>
            </div>

            {/* Field selector */}
            <div>
              <label className="text-xs font-mono text-text-muted mb-1 block">Field to update</label>
              <select value={bulkField} onChange={e => { setBulkField(e.target.value); setBulkValue('') }}
                className="input-field font-mono text-sm w-full">
                <option value="no">Periode</option>
                <option value="status">Status</option>
                <option value="severity">Severity</option>
                <option value="product_id">Product</option>
                <option value="finding_date">Finding Date</option>
                <option value="resolution_date">Resolution Date</option>
                <option value="fixing_date">Fixing Date</option>
              </select>
            </div>

            {/* Value selector based on field */}
            <div>
              <label className="text-xs font-mono text-text-muted mb-1 block">New Value</label>
              {bulkField === 'no' && (
                <input type="number" value={bulkValue} onChange={e => setBulkValue(e.target.value)}
                  placeholder="e.g. 2025" min="2000" max="2099"
                  className="input-field font-mono text-sm w-full" />
              )}
              {bulkField === 'status' && (
                <select value={bulkValue} onChange={e => setBulkValue(e.target.value)}
                  className="input-field font-mono text-sm w-full">
                  <option value="">-- Select Status --</option>
                  {allStatuses.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              )}
              {bulkField === 'severity' && (
                <select value={bulkValue} onChange={e => setBulkValue(e.target.value)}
                  className="input-field font-mono text-sm w-full">
                  <option value="">-- Select Severity --</option>
                  {['critical','high','medium','low','informational'].map(s => (
                    <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>
                  ))}
                </select>
              )}
              {bulkField === 'product_id' && (
                <select value={bulkValue} onChange={e => setBulkValue(e.target.value)}
                  className="input-field font-mono text-sm w-full">
                  <option value="">-- Select Product --</option>
                  {products
                    .filter((p:any) => !activeCompany || p.company_id === activeCompany)
                    .map((p:any) => {
                      const comp = companies.find((c:any) => c.id === p.company_id)
                      return <option key={p.id} value={p.id}>{comp?.code} — {p.name}</option>
                    })
                  }
                </select>
              )}
              {['finding_date','resolution_date','fixing_date'].includes(bulkField) && (
                <input type="date" value={bulkValue} onChange={e => setBulkValue(e.target.value)}
                  className="input-field font-mono text-sm w-full" />
              )}
            </div>

            {/* Preview */}
            <div className="p-3 rounded-lg bg-bg-tertiary">
              <p className="text-xs font-mono text-text-muted">
                Will update <span className="text-accent-primary font-bold">{selectedIds.size}</span> vulnerabilities:
              </p>
              <p className="text-xs font-mono text-text-primary mt-1">
                <span className="text-text-muted">{bulkField}</span> → <span className="text-severity-low font-bold">
                  {bulkField === 'no' ? bulkValue || '(none)' :
                   bulkField === 'product_id'
                    ? products.find((p:any) => p.id === bulkValue)?.name || '(none)'
                    : bulkValue || '(none)'}
                </span>
              </p>
            </div>

            <button
              onClick={() => bulkUpdate.mutate({ ids: [...selectedIds], field: bulkField, value: bulkValue })}
              disabled={!bulkValue || bulkUpdate.isPending}
              className="w-full btn-primary py-2 font-mono font-bold rounded-lg disabled:opacity-50">
              {bulkUpdate.isPending ? 'Updating...' : `Update ${selectedIds.size} Vulnerabilities`}
            </button>
          </div>
        </div>
      )}

      {/* CVSS Calculator */}
      {showCVSS && (
        <div className="fixed inset-0 bg-black bg-opacity-60 z-50 flex items-center justify-center p-4">
          <div className="card p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto space-y-4">
            <div className="flex items-center justify-between">
              <p className="font-mono font-bold text-text-primary">CVSS Calculator</p>
              <button onClick={() => setShowCVSS(false)}><X size={16} className="text-text-muted" /></button>
            </div>
            <CVSSCalculator version="4.0" onApply={(score, vector, version) => {
              setNewVuln((p:any) => ({...p, cvss_score: String(score), cvss_vector: vector, cvss_version: version}))
              setShowCVSS(false)
              setShowAddVuln(true)
              toast.success(`CVSS ${version} — Score: ${score} applied`)
            }} />
          </div>
        </div>
      )}
      {/* POC Modal */}
      {pocItem && pocData !== null && (
        <PocModal
          vulnItem={pocItem}
          existingPocs={pocData || []}
          onClose={() => { setPocItem(null); setPocData(null) }}
          onRefresh={() => qc.invalidateQueries({queryKey:['vuln-reports']})}
        />
      )}
    </div>
  )
}
