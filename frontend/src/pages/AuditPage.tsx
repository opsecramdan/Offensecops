import { ClipboardList, Download, Search } from 'lucide-react'
import { useState } from 'react'
import { format } from 'date-fns'

const mockLogs = [
  { id: '1', user: 'operator1', action: 'scan.create', resource: 'api.target.com', ip: '10.16.91.50', code: 201, ts: new Date().toISOString() },
  { id: '2', user: 'operator2', action: 'auth.login', resource: 'session', ip: '10.16.91.55', code: 200, ts: new Date(Date.now() - 300000).toISOString() },
  { id: '3', user: 'admin', action: 'tool.enable', resource: 'nuclei', ip: '10.16.91.126', code: 200, ts: new Date(Date.now() - 600000).toISOString() },
  { id: '4', user: 'operator1', action: 'sqli.execute', resource: 'shop.target.com', ip: '10.16.91.50', code: 202, ts: new Date(Date.now() - 900000).toISOString() },
  { id: '5', user: 'unknown', action: 'auth.login', resource: 'session', ip: '203.0.113.42', code: 401, ts: new Date(Date.now() - 1200000).toISOString() },
]

export default function AuditPage() {
  const [search, setSearch] = useState('')
  const filtered = mockLogs.filter(l => l.user.includes(search) || l.action.includes(search) || l.resource.includes(search))

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
            <ClipboardList size={24} className="text-accent-primary" /> Audit Log
          </h1>
          <p className="text-text-muted text-sm font-mono mt-1">Immutable activity trail</p>
        </div>
        <button className="btn-secondary flex items-center gap-2"><Download size={14} /> Export CSV</button>
      </div>

      <div className="card p-4 flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input type="text" placeholder="Filter logs..." value={search} onChange={e => setSearch(e.target.value)} className="input-field pl-9" />
        </div>
      </div>

      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border-default">
              <th className="text-left px-4 py-3 text-text-muted text-xs font-mono uppercase">Timestamp</th>
              <th className="text-left px-4 py-3 text-text-muted text-xs font-mono uppercase">User</th>
              <th className="text-left px-4 py-3 text-text-muted text-xs font-mono uppercase">Action</th>
              <th className="text-left px-4 py-3 text-text-muted text-xs font-mono uppercase">Resource</th>
              <th className="text-left px-4 py-3 text-text-muted text-xs font-mono uppercase">IP Address</th>
              <th className="text-left px-4 py-3 text-text-muted text-xs font-mono uppercase">Code</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-default font-mono text-xs">
            {filtered.map(log => (
              <tr key={log.id} className={`hover:bg-bg-hover transition-colors ${log.code >= 400 ? 'bg-severity-critical bg-opacity-5' : ''}`}>
                <td className="px-4 py-2.5 text-text-muted">{format(new Date(log.ts), 'MMM d HH:mm:ss')}</td>
                <td className="px-4 py-2.5 text-accent-primary">{log.user}</td>
                <td className="px-4 py-2.5 text-text-primary">{log.action}</td>
                <td className="px-4 py-2.5 text-text-secondary">{log.resource}</td>
                <td className="px-4 py-2.5 text-text-muted">{log.ip}</td>
                <td className="px-4 py-2.5">
                  <span className={log.code < 300 ? 'text-accent-primary' : log.code < 400 ? 'text-severity-medium' : 'text-severity-critical'}>
                    {log.code}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
