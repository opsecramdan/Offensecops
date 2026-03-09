import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  FileText, Download, Eye, Shield, AlertTriangle,
  BarChart3, Target, CheckCircle, Clock, RefreshCw,
  ChevronDown, Filter, Zap
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'

const SEV_META: Record<string, { color: string; label: string }> = {
  critical: { color: '#ef4444', label: 'Critical' },
  high:     { color: '#f97316', label: 'High' },
  medium:   { color: '#eab308', label: 'Medium' },
  low:      { color: '#22c55e', label: 'Low' },
  info:     { color: '#3b82f6', label: 'Info' },
}

export default function ReportsPage() {
  const [selectedJobs, setSelectedJobs] = useState<string[]>([])
  const [company, setCompany] = useState('OffenSecOps')
  const [author, setAuthor] = useState('Red Team')
  const [includeInfo, setIncludeInfo] = useState(false)
  const [generating, setGenerating] = useState(false)

  const { data: history = [], isLoading: histLoading } = useQuery({
    queryKey: ['scan-engine-history'],
    queryFn: () => api.get('/scan-engine/history').then(r => r.data),
    refetchInterval: 30000,
  })

  const { data: preview, isLoading: previewLoading, refetch: refetchPreview } = useQuery({
    queryKey: ['report-preview', selectedJobs],
    queryFn: () => {
      const params = selectedJobs.length > 0
        ? `?scan_job_ids=${selectedJobs.join(',')}`
        : ''
      return api.get(`/reports/preview${params}`).then(r => r.data)
    },
    staleTime: 10000,
  })

  const toggleJob = (id: string) => {
    setSelectedJobs(prev =>
      prev.includes(id) ? prev.filter(j => j !== id) : [...prev, id]
    )
  }

  const handleGenerate = async () => {
    setGenerating(true)
    try {
      const res = await api.post('/reports/generate', {
        scan_job_ids: selectedJobs.length > 0 ? selectedJobs : null,
        company,
        author,
        include_info: includeInfo,
      }, { responseType: 'blob' })

      // Download PDF
      const url = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `pentest_report_${new Date().toISOString().slice(0,10)}.pdf`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      const findingCount = res.headers['x-finding-count'] || '?'
      toast.success(`Report generated — ${findingCount} findings`)
    } catch (e: any) {
      toast.error('Report generation failed')
      console.error(e)
    } finally {
      setGenerating(false)
    }
  }

  const rs = preview?.risk_score ?? 0
  const rsColor = rs >= 70 ? '#ef4444' : rs >= 40 ? '#f97316' : rs >= 20 ? '#eab308' : '#22c55e'
  const total = preview?.total_findings ?? 0
  const sevBreak = preview?.severity_breakdown ?? {}

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
            <FileText size={24} className="text-accent-primary" /> Reports
          </h1>
          <p className="text-text-muted text-sm font-mono mt-1">
            Generate professional PDF pentest reports from scan findings
          </p>
        </div>
      </div>

      <div className="flex gap-5 flex-col lg:flex-row">
        {/* ── Left: Config ───────────────────────────────── */}
        <div className="w-full lg:w-80 flex-shrink-0 space-y-4">

          {/* Report Settings */}
          <div className="card p-4 space-y-3">
            <p className="text-xs font-mono font-bold text-accent-primary flex items-center gap-1.5">
              <FileText size={12} /> Report Settings
            </p>
            <div className="space-y-2">
              <div>
                <label className="text-xs font-mono text-text-muted">Company Name</label>
                <input value={company} onChange={e => setCompany(e.target.value)}
                  className="input-field font-mono text-sm mt-1"
                  placeholder="OffenSecOps" />
              </div>
              <div>
                <label className="text-xs font-mono text-text-muted">Prepared By</label>
                <input value={author} onChange={e => setAuthor(e.target.value)}
                  className="input-field font-mono text-sm mt-1"
                  placeholder="Red Team" />
              </div>
              <label className="flex items-center gap-2 cursor-pointer mt-1">
                <input type="checkbox" checked={includeInfo}
                  onChange={e => setIncludeInfo(e.target.checked)}
                  className="w-3.5 h-3.5 accent-indigo-500" />
                <span className="text-xs font-mono text-text-muted">Include info findings</span>
              </label>
            </div>
          </div>

          {/* Scan Jobs selector */}
          <div className="card p-4 space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs font-mono font-bold text-accent-primary flex items-center gap-1.5">
                <Target size={12} /> Scan Jobs
              </p>
              {selectedJobs.length > 0 && (
                <button onClick={() => setSelectedJobs([])}
                  className="text-xs font-mono text-text-muted hover:text-text-primary">
                  Clear ({selectedJobs.length})
                </button>
              )}
            </div>
            <p className="text-xs font-mono text-text-muted">
              {selectedJobs.length === 0
                ? 'All scans (no filter)'
                : `${selectedJobs.length} selected`}
            </p>
            <div className="space-y-1 max-h-64 overflow-y-auto">
              {histLoading ? (
                <p className="text-xs font-mono text-text-muted text-center py-4">Loading...</p>
              ) : history.length === 0 ? (
                <p className="text-xs font-mono text-text-muted text-center py-4">No scan history</p>
              ) : (
                history.map((job: any) => {
                  const selected = selectedJobs.includes(job.job_id)
                  return (
                    <button key={job.job_id} onClick={() => toggleJob(job.job_id)}
                      className={`w-full text-left p-2.5 rounded-lg border transition-all ${
                        selected
                          ? 'border-accent-primary bg-accent-primary bg-opacity-10'
                          : 'border-border-default hover:border-border-muted'
                      }`}>
                      <div className="flex items-center justify-between">
                        <p className="text-xs font-mono text-text-primary truncate flex-1">
                          {job.target}
                        </p>
                        {selected && <CheckCircle size={11} className="text-accent-primary flex-shrink-0 ml-1" />}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className={`text-xs font-mono ${
                          job.status === 'completed' ? 'text-severity-low' :
                          job.status === 'failed' ? 'text-severity-critical' : 'text-text-muted'
                        }`}>{job.status}</span>
                        <span className="text-xs font-mono text-text-muted">
                          {job.finding_count} findings
                        </span>
                        <span className="text-xs font-mono text-text-muted ml-auto">
                          {job.created_at ? new Date(job.created_at).toLocaleDateString() : ''}
                        </span>
                      </div>
                    </button>
                  )
                })
              )}
            </div>
          </div>

          {/* Generate button */}
          <button onClick={handleGenerate} disabled={generating || total === 0}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-lg font-mono text-sm font-bold btn-primary disabled:opacity-50 transition-all">
            {generating
              ? <><RefreshCw size={14} className="animate-spin" />Generating PDF...</>
              : <><Download size={14} />Generate Report</>
            }
          </button>
          {total === 0 && !previewLoading && (
            <p className="text-xs font-mono text-text-muted text-center">
              No findings to report. Run a scan first.
            </p>
          )}
        </div>

        {/* ── Right: Preview ─────────────────────────────── */}
        <div className="flex-1 min-w-0 space-y-4">

          {/* Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Total Findings', value: total, color: '#6366f1' },
              { label: 'Risk Score', value: `${rs}/100`, color: rsColor },
              { label: 'OWASP Categories', value: preview?.owasp_categories_affected ?? 0, color: '#06b6d4' },
              { label: 'Scan Jobs', value: selectedJobs.length || history.length, color: '#8b5cf6' },
            ].map(({ label, value, color }) => (
              <div key={label} className="card p-4 text-center">
                <p className="text-2xl font-display font-bold" style={{ color }}>{value}</p>
                <p className="text-xs font-mono text-text-muted mt-1">{label}</p>
              </div>
            ))}
          </div>

          {/* Severity breakdown */}
          {total > 0 && (
            <div className="card p-4 space-y-3">
              <p className="text-xs font-mono font-bold text-text-primary">Finding Distribution</p>
              {/* Bar */}
              <div className="flex h-3 rounded-full overflow-hidden gap-px">
                {Object.entries(SEV_META).map(([sev, meta]) => {
                  const count = sevBreak[sev] || 0
                  if (count === 0) return null
                  const pct = (count / total) * 100
                  return (
                    <div key={sev} style={{ width: `${pct}%`, backgroundColor: meta.color }}
                      title={`${meta.label}: ${count}`} />
                  )
                })}
              </div>
              <div className="flex flex-wrap gap-3">
                {Object.entries(SEV_META).map(([sev, meta]) => {
                  const count = sevBreak[sev] || 0
                  if (count === 0) return null
                  return (
                    <div key={sev} className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: meta.color }} />
                      <span className="text-xs font-mono text-text-muted">
                        {count} {meta.label}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* OWASP coverage */}
          {Object.keys(preview?.owasp_coverage ?? {}).length > 0 && (
            <div className="card p-4 space-y-3">
              <p className="text-xs font-mono font-bold text-text-primary flex items-center gap-1.5">
                <Shield size={12} className="text-accent-primary" /> OWASP Coverage
              </p>
              <div className="grid grid-cols-2 gap-1.5">
                {Object.entries(preview.owasp_coverage).map(([cat, count]: any) => (
                  <div key={cat}
                    className="flex items-center justify-between p-2 rounded-lg border border-severity-critical border-opacity-30 bg-severity-critical bg-opacity-5">
                    <span className="text-xs font-mono font-bold text-accent-primary">{cat}</span>
                    <span className="text-xs font-mono text-severity-critical font-bold">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Report preview card */}
          <div className="card p-6 space-y-4 border-dashed">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-accent-primary bg-opacity-20 flex items-center justify-center">
                <FileText size={20} className="text-accent-primary" />
              </div>
              <div>
                <p className="font-mono font-bold text-text-primary">Pentest Security Report</p>
                <p className="text-xs font-mono text-text-muted">PDF · A4 · Professional layout</p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono text-text-muted">
              {[
                ['Cover Page', 'Risk score, target, date'],
                ['Executive Summary', 'Stats, severity chart, targets'],
                ['OWASP Top 10', 'Coverage mapping table'],
                ['Technical Findings', 'Full detail per finding'],
                ['Methodology', 'Tools & modules used'],
                ['Disclaimer', 'Legal & scope notes'],
              ].map(([section, desc]) => (
                <div key={section} className="flex items-start gap-1.5 p-2 rounded-lg bg-bg-tertiary">
                  <CheckCircle size={10} className="text-severity-low mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-text-primary font-bold">{section}</p>
                    <p className="text-text-muted">{desc}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-2 p-3 rounded-lg border border-accent-primary border-opacity-30 bg-accent-primary bg-opacity-5">
              <Zap size={12} className="text-accent-primary" />
              <p className="text-xs font-mono text-accent-primary">
                Company: <b>{company}</b> · Author: <b>{author}</b>
                {selectedJobs.length > 0 && ` · ${selectedJobs.length} job(s) selected`}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
