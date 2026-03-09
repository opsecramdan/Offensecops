import { useQuery } from '@tanstack/react-query'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell, Legend,
} from 'recharts'
import {
  Target, Shield, Activity, AlertTriangle, Clock,
  CheckCircle, XCircle, Loader, Zap, Server, TrendingUp,
  RefreshCw, ChevronRight,
} from 'lucide-react'
import { api } from '../lib/api'
import { useAuthStore } from '../store/authStore'

// ── Colors ───────────────────────────────────────────────────
const SEV_COLORS = {
  critical: '#ef4444', high: '#f97316',
  medium: '#f59e0b', low: '#3b82f6', informational: '#6b7280',
}
const STATUS_ICON: Record<string, any> = {
  completed: <CheckCircle size={13} className="text-severity-low" />,
  running:   <Loader size={13} className="text-accent-primary animate-spin" />,
  queued:    <Clock size={13} className="text-text-muted" />,
  failed:    <XCircle size={13} className="text-severity-critical" />,
  cancelled: <XCircle size={13} className="text-text-muted" />,
}
const STATUS_COLOR: Record<string, string> = {
  completed: 'text-severity-low', running: 'text-accent-primary',
  queued: 'text-text-muted', failed: 'text-severity-critical', cancelled: 'text-text-muted',
}

// ── Stat Card ────────────────────────────────────────────────
function StatCard({ label, value, sub, icon: Icon, color = 'text-text-primary', alert = false }: any) {
  return (
    <div className={`card p-5 flex items-start gap-4 ${alert ? 'border-severity-critical border-opacity-50' : ''}`}>
      <div className={`p-2.5 rounded-lg bg-bg-tertiary ${color}`}>
        <Icon size={20} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-text-muted text-xs font-mono uppercase tracking-wider">{label}</p>
        <p className={`text-3xl font-display font-bold mt-0.5 ${color}`}>{value ?? '—'}</p>
        {sub && <p className="text-text-muted text-xs font-mono mt-1">{sub}</p>}
      </div>
    </div>
  )
}

// ── Tool Health Grid ─────────────────────────────────────────
function ToolHealthGrid({ tools }: { tools: any[] }) {
  const byCategory: Record<string, any[]> = {}
  tools.forEach(t => {
    if (!byCategory[t.category]) byCategory[t.category] = []
    byCategory[t.category].push(t)
  })

  const healthColor = (s: string) => ({
    healthy: 'text-severity-low bg-severity-low',
    unavailable: 'text-severity-critical bg-severity-critical',
    unknown: 'text-text-muted bg-text-muted',
  }[s] || 'text-text-muted bg-text-muted')

  return (
    <div className="space-y-3">
      {Object.entries(byCategory).map(([cat, catTools]) => (
        <div key={cat}>
          <p className="text-text-muted text-xs font-mono uppercase mb-2">{cat}</p>
          <div className="flex flex-wrap gap-2">
            {catTools.map((t: any) => (
              <div key={t.id} className="flex items-center gap-1.5 bg-bg-tertiary border border-border-default rounded-md px-2.5 py-1.5">
                <div className={`w-1.5 h-1.5 rounded-full ${healthColor(t.health_status)} bg-opacity-80`} />
                <span className="text-xs font-mono text-text-secondary">{t.name}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Custom Tooltip ───────────────────────────────────────────
function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-bg-secondary border border-border-default rounded-lg p-3 shadow-xl">
      <p className="text-text-muted text-xs font-mono mb-2">{label}</p>
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center gap-2 text-xs font-mono">
          <div className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          <span className="text-text-secondary capitalize">{p.dataKey}:</span>
          <span className="text-text-primary font-bold">{p.value}</span>
        </div>
      ))}
    </div>
  )
}

// ── Main Dashboard ───────────────────────────────────────────
export default function DashboardPage() {
  const { user } = useAuthStore()

  const statsQ = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => api.get('/dashboard/stats').then(r => r.data),
    refetchInterval: (data: any) => data?.active_scans > 0 ? 30000 : false,
    staleTime: 30000,
  })

  const trendQ = useQuery({
    queryKey: ['vuln-trend'],
    queryFn: () => api.get('/dashboard/vuln-trend').then(r => r.data),
    refetchInterval: false,
    staleTime: 300000, // 5 menit
  })

  const activityQ = useQuery({
    queryKey: ['scan-activity'],
    queryFn: () => api.get('/dashboard/scan-activity').then(r => r.data),
    refetchInterval: false,
    staleTime: 60000,
  })

  const toolsQ = useQuery({
    queryKey: ['tool-health'],
    queryFn: () => api.get('/dashboard/tool-health').then(r => r.data),
    refetchInterval: false,
    staleTime: 300000,
  })

  const stats = statsQ.data
  const trend = trendQ.data || []
  const activity = activityQ.data || []
  const tools = toolsQ.data || []

  const isLoading = statsQ.isLoading

  // Severity pie data
  const pieData = stats ? [
    { name: 'Critical', value: stats.critical_vulns, color: SEV_COLORS.critical },
    { name: 'High',     value: stats.high_vulns,     color: SEV_COLORS.high },
    { name: 'Medium',   value: stats.medium_vulns,   color: SEV_COLORS.medium },
    { name: 'Low',      value: stats.low_vulns,       color: SEV_COLORS.low },
  ].filter(d => d.value > 0) : []

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary">
            Welcome back, <span className="text-accent-primary">{user?.full_name || user?.username}</span>
          </h1>
          <p className="text-text-muted text-sm font-mono mt-1">
            {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
          </p>
        </div>
        <button
          onClick={() => { statsQ.refetch(); trendQ.refetch(); activityQ.refetch() }}
          className="btn-secondary flex items-center gap-2"
        >
          <RefreshCw size={14} className={statsQ.isFetching ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Stat Cards */}
      {isLoading ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="card p-5 h-28 animate-pulse bg-bg-tertiary" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Total Targets" value={stats?.total_targets} icon={Target}
            color="text-accent-primary" sub="registered assets" />
          <StatCard label="Active Scans" value={stats?.active_scans} icon={Activity}
            color="text-accent-primary"
            sub={stats?.active_scans > 0 ? 'running now' : 'no active scans'} />
          <StatCard label="Total Findings" value={stats?.total_vulns} icon={Shield}
            color="text-text-primary" sub={`${stats?.resolved_vulns} resolved`} />
          <StatCard label="SLA Breached" value={stats?.sla_breached} icon={AlertTriangle}
            color="text-severity-critical" alert={stats?.sla_breached > 0}
            sub="require immediate action" />
          <StatCard label="Critical" value={stats?.critical_vulns} icon={AlertTriangle}
            color="text-severity-critical" />
          <StatCard label="High" value={stats?.high_vulns} icon={AlertTriangle}
            color="text-severity-high" />
          <StatCard label="Medium" value={stats?.medium_vulns} icon={AlertTriangle}
            color="text-severity-medium" />
          <StatCard label="Tools Online" value={`${stats?.tools_healthy}/${stats?.tools_total}`}
            icon={Server} color="text-severity-low"
            sub={stats?.tools_healthy === stats?.tools_total ? 'all healthy' : 'some unavailable'} />
        </div>
      )}

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Vuln Trend */}
        <div className="lg:col-span-2 card p-5">
          <div className="flex items-center justify-between mb-5">
            <div>
              <h2 className="font-display font-semibold text-text-primary flex items-center gap-2">
                <TrendingUp size={16} className="text-accent-primary" /> Vulnerability Trend
              </h2>
              <p className="text-text-muted text-xs font-mono mt-0.5">Last 30 days</p>
            </div>
          </div>
          {trend.length === 0 ? (
            <div className="flex items-center justify-center h-40 text-text-muted text-sm">
              No data yet — add vulnerabilities to see trend
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trend} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                <defs>
                  {Object.entries(SEV_COLORS).slice(0, 4).map(([key, color]) => (
                    <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={color} stopOpacity={0} />
                    </linearGradient>
                  ))}
                </defs>
                <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false} axisLine={false} interval="preserveStartEnd" />
                <YAxis tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTooltip />} />
                {['critical', 'high', 'medium', 'low'].map(sev => (
                  <Area key={sev} type="monotone" dataKey={sev}
                    stroke={SEV_COLORS[sev as keyof typeof SEV_COLORS]}
                    fill={`url(#grad-${sev})`} strokeWidth={2} dot={false} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Severity Pie */}
        <div className="card p-5">
          <h2 className="font-display font-semibold text-text-primary flex items-center gap-2 mb-5">
            <Shield size={16} className="text-accent-primary" /> By Severity
          </h2>
          {pieData.length === 0 ? (
            <div className="flex items-center justify-center h-40 text-text-muted text-sm text-center">
              No open vulnerabilities
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70}
                    dataKey="value" paddingAngle={3}>
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(val: any, name: any) => [val, name]} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2 mt-2">
                {pieData.map(d => (
                  <div key={d.name} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                      <span className="text-xs font-mono text-text-secondary">{d.name}</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-text-primary">{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Scan Activity + Recent Scans Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Weekly scan bar chart */}
        <div className="card p-5">
          <h2 className="font-display font-semibold text-text-primary flex items-center gap-2 mb-5">
            <Activity size={16} className="text-accent-primary" /> Scan Activity
          </h2>
          {activity.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-text-muted text-sm">No scan data</div>
          ) : (
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={activity} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                <XAxis dataKey="day" tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} />
                <Bar dataKey="completed" stackId="a" fill={SEV_COLORS.low} radius={[0,0,0,0]} />
                <Bar dataKey="failed" stackId="a" fill={SEV_COLORS.critical} radius={[2,2,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
          <div className="flex items-center gap-4 mt-3">
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full" style={{ background: SEV_COLORS.low }} />
              <span className="text-xs font-mono text-text-muted">Completed</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full" style={{ background: SEV_COLORS.critical }} />
              <span className="text-xs font-mono text-text-muted">Failed</span>
            </div>
          </div>
        </div>

        {/* Recent scans */}
        <div className="lg:col-span-2 card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display font-semibold text-text-primary flex items-center gap-2">
              <Zap size={16} className="text-accent-primary" /> Recent Scans
            </h2>
            <a href="/scans" className="text-xs text-accent-primary font-mono hover:underline flex items-center gap-1">
              View all <ChevronRight size={11} />
            </a>
          </div>
          {!stats?.recent_scans?.length ? (
            <div className="flex items-center justify-center py-8 text-text-muted text-sm">
              No scans yet — launch your first scan
            </div>
          ) : (
            <div className="space-y-2">
              {stats.recent_scans.map((s: any) => (
                <div key={s.id} className="flex items-center gap-3 p-3 bg-bg-tertiary rounded-lg border border-border-default hover:border-border-muted transition-colors">
                  <div className="flex-shrink-0">{STATUS_ICON[s.status]}</div>
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-text-primary truncate">{s.target}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className={`text-xs font-mono ${STATUS_COLOR[s.status]}`}>{s.status}</span>
                      {s.tools?.length > 0 && (
                        <span className="text-xs text-text-muted font-mono">
                          [{s.tools.slice(0, 2).join(', ')}{s.tools.length > 2 ? ` +${s.tools.length - 2}` : ''}]
                        </span>
                      )}
                    </div>
                  </div>
                  {s.status === 'running' && (
                    <div className="w-16 h-1.5 bg-bg-secondary rounded-full overflow-hidden flex-shrink-0">
                      <div className="h-full bg-accent-primary rounded-full transition-all"
                        style={{ width: `${s.progress || 0}%` }} />
                    </div>
                  )}
                  <span className="text-xs text-text-muted font-mono flex-shrink-0">
                    {s.started ? new Date(s.started).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Tool Health */}
      <div className="card p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-display font-semibold text-text-primary flex items-center gap-2">
            <Server size={16} className="text-accent-primary" /> Tool Health
          </h2>
          <div className="flex items-center gap-3 text-xs font-mono text-text-muted">
            <span className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full bg-severity-low" /> healthy
            </span>
            <span className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full bg-severity-critical" /> unavailable
            </span>
            <span className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full bg-text-muted" /> unknown
            </span>
          </div>
        </div>
        {tools.length === 0 ? (
          <p className="text-text-muted text-sm">No tools registered. Seed tools via API.</p>
        ) : (
          <ToolHealthGrid tools={tools} />
        )}
      </div>
    </div>
  )
}
