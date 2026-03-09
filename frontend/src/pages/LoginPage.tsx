import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Zap, Lock, User, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { useAuthStore } from '../store/authStore'
import { api } from '../lib/api'
import toast from 'react-hot-toast'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const { setAuth } = useAuthStore()
  const navigate = useNavigate()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const res = await api.post('/auth/login', { username, password })
      const { user, access_token, refresh_token } = res.data
      setAuth(user, access_token, refresh_token)
      toast.success(`Welcome back, ${user.username}`)
      navigate('/')
    } catch (err: any) {
      const msg = err.response?.data?.detail || 'Login failed. Check your credentials.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen cyber-bg flex items-center justify-center relative overflow-hidden">
      {/* Background decorative elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-accent-primary opacity-3 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-accent-purple opacity-5 rounded-full blur-3xl" />

        {/* Corner brackets */}
        <div className="absolute top-8 left-8 w-16 h-16 border-t-2 border-l-2 border-accent-primary opacity-20" />
        <div className="absolute top-8 right-8 w-16 h-16 border-t-2 border-r-2 border-accent-primary opacity-20" />
        <div className="absolute bottom-8 left-8 w-16 h-16 border-b-2 border-l-2 border-accent-primary opacity-20" />
        <div className="absolute bottom-8 right-8 w-16 h-16 border-b-2 border-r-2 border-accent-primary opacity-20" />
      </div>

      {/* Login Card */}
      <div className="relative w-full max-w-md mx-4">
        {/* Glow effect behind card */}
        <div className="absolute inset-0 bg-accent-primary opacity-5 rounded-2xl blur-xl" />

        <div className="relative bg-bg-secondary border border-border-default rounded-2xl p-8 shadow-2xl">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-bg-tertiary border border-border-active rounded-2xl mb-4 relative">
              <Zap size={28} className="text-accent-primary" />
              <span className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-severity-critical rounded-full border-2 border-bg-secondary animate-pulse" />
            </div>
            <h1 className="font-display font-bold text-2xl text-text-primary">OffenSecOps</h1>
            <p className="text-text-muted text-sm font-mono mt-1">Enterprise Red Team Platform</p>
          </div>

          {/* Warning Banner */}
          <div className="bg-severity-critical bg-opacity-10 border border-severity-critical border-opacity-30 rounded-lg p-3 mb-6">
            <div className="flex items-center gap-2">
              <AlertCircle size={14} className="text-severity-critical flex-shrink-0" />
              <p className="text-severity-critical text-xs font-mono">
                AUTHORIZED PERSONNEL ONLY. All activity is logged and monitored.
              </p>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-text-secondary text-xs font-mono mb-1.5 uppercase tracking-wider">
                Username
              </label>
              <div className="relative">
                <User size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="input-field pl-9"
                  placeholder="operator_username"
                  autoComplete="username"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-text-secondary text-xs font-mono mb-1.5 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                <input
                  type={showPass ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-field pl-9 pr-10"
                  placeholder="••••••••••••"
                  autoComplete="current-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors"
                >
                  {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="bg-severity-critical bg-opacity-10 border border-severity-critical border-opacity-30 rounded p-3">
                <p className="text-severity-critical text-xs font-mono">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-primary py-3 mt-2 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 border-2 border-bg-primary border-t-transparent rounded-full animate-spin" />
                  Authenticating...
                </>
              ) : (
                <>
                  <Lock size={14} />
                  Authenticate
                </>
              )}
            </button>
          </form>

          {/* Footer */}
          <p className="text-center text-text-muted text-xs font-mono mt-6">
            v1.0.0 · OffenSecOps Platform · {new Date().getFullYear()}
          </p>
        </div>
      </div>
    </div>
  )
}
