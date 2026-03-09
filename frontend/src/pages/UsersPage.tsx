import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Users, Plus, Search, Shield, X, Edit, Trash2,
  ChevronDown, Lock, Unlock, RefreshCw, Key, UserCheck, UserX
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import { useAuthStore } from '../store/authStore'

// ── Constants ─────────────────────────────────────────────────
const ROLES = ['admin','manager','pentester','viewer','auditor']

const ROLE_COLOR: Record<string, string> = {
  admin:     'text-severity-critical bg-severity-critical',
  manager:   'text-severity-high bg-severity-high',
  pentester: 'text-accent-primary bg-accent-primary',
  viewer:    'text-text-secondary bg-text-secondary',
  auditor:   'text-severity-medium bg-severity-medium',
}

const ROLE_DESC: Record<string, string> = {
  admin:     'Full access — manage users, all data',
  manager:   'Add targets, run scans, view all vulns',
  pentester: 'Run scans, SQLi module, manage findings',
  viewer:    'Read-only access to vulns & reports',
  auditor:   'View vulns, audit logs, export reports',
}

function RoleBadge({ role }: { role: string }) {
  const cls = ROLE_COLOR[role] || 'text-text-muted bg-text-muted'
  return (
    <span className={`text-xs font-mono font-semibold ${cls} bg-opacity-10 border border-current border-opacity-30 px-2 py-0.5 rounded capitalize`}>
      {role}
    </span>
  )
}

// ── Action Dropdown ───────────────────────────────────────────
function ActionMenu({ user, currentUserId, onEdit, onResetPwd, onToggleActive, onUnlock, onDelete }: {
  user: any, currentUserId: string,
  onEdit: () => void, onResetPwd: () => void,
  onToggleActive: () => void, onUnlock: () => void, onDelete: () => void
}) {
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState({ top: 0, right: 0 })
  const btnRef = useRef<HTMLButtonElement>(null)
  const isSelf = user.id === currentUserId
  const isLocked = user.locked_until && new Date(user.locked_until) > new Date()

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
          <div className="fixed z-50 bg-bg-secondary border border-border-default rounded-lg shadow-2xl min-w-48 py-1"
            style={{ top: pos.top, right: pos.right }}>
            <button onClick={() => { setOpen(false); onEdit() }}
              className="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs font-mono text-text-secondary hover:bg-bg-hover transition-colors">
              <Edit size={12} /> Edit Role & Info
            </button>
            <button onClick={() => { setOpen(false); onResetPwd() }}
              className="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs font-mono text-text-secondary hover:bg-bg-hover transition-colors">
              <Key size={12} /> Reset Password
            </button>
            {isLocked && (
              <button onClick={() => { setOpen(false); onUnlock() }}
                className="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs font-mono text-severity-medium hover:bg-bg-hover transition-colors">
                <Unlock size={12} /> Unlock Account
              </button>
            )}
            {!isSelf && (
              <button onClick={() => { setOpen(false); onToggleActive() }}
                className={`w-full flex items-center gap-2.5 px-4 py-2.5 text-xs font-mono hover:bg-bg-hover transition-colors ${
                  user.is_active ? 'text-severity-medium' : 'text-severity-low'
                }`}>
                {user.is_active ? <><UserX size={12} /> Deactivate</> : <><UserCheck size={12} /> Activate</>}
              </button>
            )}
            {!isSelf && (
              <>
                <div className="border-t border-border-default my-1" />
                <button onClick={() => { setOpen(false); onDelete() }}
                  className="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs font-mono text-severity-critical hover:bg-bg-hover transition-colors">
                  <Trash2 size={12} /> Delete User
                </button>
              </>
            )}
          </div>
        </>
      )}
    </div>
  )
}

// ── Create / Edit Modal ───────────────────────────────────────
function UserModal({ user, onClose, onSuccess }: { user?: any, onClose: () => void, onSuccess: () => void }) {
  const isEdit = !!user
  const [form, setForm] = useState({
    username: user?.username || '',
    email: user?.email || '',
    full_name: user?.full_name || '',
    password: '',
    role: user?.role || 'pentester',
  })
  const [loading, setLoading] = useState(false)
  const set = (k: string, v: string) => setForm(f => ({ ...f, [k]: v }))

  const handleSubmit = async () => {
    if (!form.username || !form.email) { toast.error('Username dan email wajib diisi'); return }
    if (!isEdit && form.password.length < 8) { toast.error('Password minimal 8 karakter'); return }
    setLoading(true)
    try {
      if (isEdit) {
        await api.patch(`/users/${user.id}`, {
          email: form.email, full_name: form.full_name, role: form.role,
        })
        toast.success('User updated')
      } else {
        await api.post('/users/', form)
        toast.success(`User ${form.username} created`)
      }
      onSuccess(); onClose()
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Failed')
    } finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-default rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between p-5 border-b border-border-default">
          <h2 className="font-display font-bold text-text-primary flex items-center gap-2">
            {isEdit ? <Edit size={16} className="text-accent-primary" /> : <Plus size={16} className="text-accent-primary" />}
            {isEdit ? `Edit: ${user.username}` : 'Create User'}
          </h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary"><X size={18} /></button>
        </div>

        <div className="p-5 space-y-4">
          {!isEdit && (
            <div>
              <label className="label-field">Username *</label>
              <input value={form.username} onChange={e => set('username', e.target.value)}
                className="input-field font-mono" placeholder="johndoe" />
            </div>
          )}
          <div>
            <label className="label-field">Email *</label>
            <input value={form.email} onChange={e => set('email', e.target.value)}
              className="input-field" placeholder="john@company.com" type="email" />
          </div>
          <div>
            <label className="label-field">Full Name</label>
            <input value={form.full_name} onChange={e => set('full_name', e.target.value)}
              className="input-field" placeholder="John Doe" />
          </div>
          {!isEdit && (
            <div>
              <label className="label-field">Password *</label>
              <input value={form.password} onChange={e => set('password', e.target.value)}
                className="input-field font-mono" placeholder="Min. 8 karakter" type="password" />
            </div>
          )}
          <div>
            <label className="label-field mb-2">Role</label>
            <div className="space-y-2">
              {ROLES.map(r => (
                <label key={r} className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                  form.role === r ? 'border-accent-primary bg-accent-primary bg-opacity-5' : 'border-border-default hover:border-border-muted'
                }`}>
                  <input type="radio" name="role" value={r} checked={form.role === r}
                    onChange={() => set('role', r)} className="mt-0.5 accent-accent-primary" />
                  <div>
                    <div className="flex items-center gap-2">
                      <RoleBadge role={r} />
                    </div>
                    <p className="text-xs text-text-muted font-mono mt-0.5">{ROLE_DESC[r]}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="flex gap-3 p-5 border-t border-border-default">
          <button onClick={onClose} className="btn-secondary flex-1">Cancel</button>
          <button onClick={handleSubmit} disabled={loading} className="btn-primary flex-1">
            {loading ? 'Saving...' : isEdit ? 'Save Changes' : 'Create User'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Reset Password Modal ──────────────────────────────────────
function ResetPasswordModal({ user, onClose }: { user: any, onClose: () => void }) {
  const [pwd, setPwd] = useState('')
  const [loading, setLoading] = useState(false)

  const handleReset = async () => {
    if (pwd.length < 8) { toast.error('Password minimal 8 karakter'); return }
    setLoading(true)
    try {
      await api.post(`/users/${user.id}/reset-password`, { new_password: pwd })
      toast.success(`Password ${user.username} berhasil direset`)
      onClose()
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Failed')
    } finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-default rounded-xl w-full max-w-sm">
        <div className="flex items-center justify-between p-5 border-b border-border-default">
          <h2 className="font-display font-bold text-text-primary flex items-center gap-2">
            <Key size={16} className="text-accent-primary" /> Reset Password
          </h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary"><X size={18} /></button>
        </div>
        <div className="p-5 space-y-4">
          <p className="text-sm text-text-secondary">
            Reset password untuk <span className="font-mono text-text-primary font-bold">{user.username}</span>
          </p>
          <div>
            <label className="label-field">New Password</label>
            <input value={pwd} onChange={e => setPwd(e.target.value)}
              className="input-field font-mono" placeholder="Min. 8 karakter" type="password" />
          </div>
        </div>
        <div className="flex gap-3 p-5 border-t border-border-default">
          <button onClick={onClose} className="btn-secondary flex-1">Cancel</button>
          <button onClick={handleReset} disabled={loading} className="btn-primary flex-1 flex items-center justify-center gap-2">
            <Key size={13} /> {loading ? 'Resetting...' : 'Reset Password'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Stats Bar ─────────────────────────────────────────────────
function UserStats({ users }: { users: any[] }) {
  const byRole = ROLES.reduce((acc, r) => ({ ...acc, [r]: users.filter(u => u.role === r).length }), {} as Record<string, number>)
  const active = users.filter(u => u.is_active).length
  const locked = users.filter(u => u.locked_until && new Date(u.locked_until) > new Date()).length

  return (
    <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-7 gap-3">
      <div className="card p-3">
        <p className="text-text-muted text-xs font-mono uppercase mb-1">Total</p>
        <p className="text-2xl font-display font-bold text-text-primary">{users.length}</p>
      </div>
      <div className="card p-3">
        <p className="text-text-muted text-xs font-mono uppercase mb-1">Active</p>
        <p className="text-2xl font-display font-bold text-severity-low">{active}</p>
      </div>
      {locked > 0 && (
        <div className="card p-3 border-severity-medium border-opacity-40">
          <p className="text-text-muted text-xs font-mono uppercase mb-1">Locked</p>
          <p className="text-2xl font-display font-bold text-severity-medium">{locked}</p>
        </div>
      )}
      {ROLES.map(r => (
        <div key={r} className="card p-3">
          <p className="text-text-muted text-xs font-mono uppercase mb-1">{r}</p>
          <p className={`text-2xl font-display font-bold ${ROLE_COLOR[r]?.split(' ')[0] || 'text-text-primary'}`}>{byRole[r] || 0}</p>
        </div>
      ))}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────
export default function UsersPage() {
  const { user: currentUser } = useAuthStore()
  const [search, setSearch] = useState('')
  const [filterRole, setFilterRole] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [editUser, setEditUser] = useState<any>(null)
  const [resetUser, setResetUser] = useState<any>(null)
  const queryClient = useQueryClient()

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['users', search, filterRole],
    queryFn: () => api.get('/users/', {
      params: { search: search || undefined, role: filterRole || undefined, limit: 100 }
    }).then(r => r.data),
  })

  const toggleActiveMutation = useMutation({
    mutationFn: (id: string) => api.post(`/users/${id}/toggle-active`),
    onSuccess: (res) => {
      toast.success(res.data.message)
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed'),
  })

  const unlockMutation = useMutation({
    mutationFn: (id: string) => api.post(`/users/${id}/unlock`),
    onSuccess: () => { toast.success('User unlocked'); queryClient.invalidateQueries({ queryKey: ['users'] }) },
    onError: () => toast.error('Failed to unlock'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/users/${id}`),
    onSuccess: () => { toast.success('User deleted'); queryClient.invalidateQueries({ queryKey: ['users'] }) },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed'),
  })

  const onSuccess = () => queryClient.invalidateQueries({ queryKey: ['users'] })
  const users = data?.items || []

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Modals */}
      {(showCreate || editUser) && (
        <UserModal user={editUser} onClose={() => { setShowCreate(false); setEditUser(null) }} onSuccess={onSuccess} />
      )}
      {resetUser && <ResetPasswordModal user={resetUser} onClose={() => setResetUser(null)} />}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
            <Users size={24} className="text-accent-primary" /> User Management
          </h1>
          <p className="text-text-muted text-sm font-mono mt-1">
            {isLoading ? '...' : `${data?.total || 0} users`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="btn-secondary p-2"><RefreshCw size={14} /></button>
          <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-2">
            <Plus size={14} /> Add User
          </button>
        </div>
      </div>

      {/* Stats */}
      {!isLoading && <UserStats users={users} />}

      {/* Filters */}
      <div className="card p-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search username, email, name..." className="input-field pl-9" />
        </div>
        <select value={filterRole} onChange={e => setFilterRole(e.target.value)} className="input-field w-36">
          <option value="">All roles</option>
          {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
        </select>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-accent-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : users.length === 0 ? (
        <div className="card p-16 text-center">
          <Users size={40} className="text-text-muted mx-auto mb-3" />
          <p className="text-text-secondary">No users found.</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border-default">
                {['User','Role','Status','Last Login','Failed Logins','Actions'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-text-muted text-xs font-mono uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border-default">
              {users.map((u: any) => {
                const isLocked = u.locked_until && new Date(u.locked_until) > new Date()
                const isSelf = u.id === currentUser?.id
                return (
                  <tr key={u.id} className="hover:bg-bg-hover transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-bg-tertiary border border-border-default flex items-center justify-center flex-shrink-0">
                          <span className="text-xs font-mono font-bold text-text-secondary">
                            {u.username.slice(0,2).toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <p className="text-sm font-mono text-text-primary font-medium">
                            {u.username} {isSelf && <span className="text-xs text-accent-primary">(you)</span>}
                          </p>
                          <p className="text-xs text-text-muted">{u.email}</p>
                          {u.full_name && <p className="text-xs text-text-muted">{u.full_name}</p>}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <RoleBadge role={u.role} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1">
                        <span className={`text-xs font-mono ${u.is_active ? 'text-severity-low' : 'text-severity-critical'}`}>
                          {u.is_active ? '● Active' : '● Inactive'}
                        </span>
                        {isLocked && (
                          <span className="flex items-center gap-1 text-xs font-mono text-severity-medium">
                            <Lock size={10} /> Locked
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs font-mono text-text-muted">
                        {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-mono font-bold ${u.failed_login_attempts >= 3 ? 'text-severity-high' : 'text-text-muted'}`}>
                        {u.failed_login_attempts || 0}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <ActionMenu
                        user={u}
                        currentUserId={currentUser?.id || ''}
                        onEdit={() => setEditUser(u)}
                        onResetPwd={() => setResetUser(u)}
                        onToggleActive={() => toggleActiveMutation.mutate(u.id)}
                        onUnlock={() => unlockMutation.mutate(u.id)}
                        onDelete={() => { if (confirm(`Delete user "${u.username}"?`)) deleteMutation.mutate(u.id) }}
                      />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* RBAC Info */}
      <div className="card p-5">
        <h2 className="font-display font-semibold text-text-primary flex items-center gap-2 mb-4">
          <Shield size={16} className="text-accent-primary" /> Role Permissions
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {ROLES.map(r => (
            <div key={r} className="p-3 bg-bg-tertiary rounded-lg border border-border-default">
              <RoleBadge role={r} />
              <p className="text-xs text-text-muted font-mono mt-2">{ROLE_DESC[r]}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
