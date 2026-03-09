import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type UserRole = 'admin' | 'manager' | 'pentester' | 'viewer' | 'auditor'

export interface User {
  id: string
  username: string
  email: string
  full_name: string
  role: UserRole
  is_active: boolean
  created_at: string
}

interface AuthState {
  user: User | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  setAuth: (user: User, accessToken: string, refreshToken: string) => void
  setAccessToken: (token: string) => void
  logout: () => void
  hasPermission: (permission: string) => boolean
}

const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  admin:     ['all'],
  manager:   ['add_targets', 'run_scans', 'view_vulns', 'mark_fp', 'export_pdf', 'view_audit'],
  pentester: ['add_targets', 'run_scans', 'sqli_module', 'view_vulns', 'mark_fp', 'export_pdf', 'view_own_audit'],
  viewer:    ['view_vulns', 'export_pdf'],
  auditor:   ['view_vulns', 'export_pdf', 'view_audit'],
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,

      setAuth: (user, accessToken, refreshToken) =>
        set({ user, accessToken, refreshToken, isAuthenticated: true }),

      setAccessToken: (token) =>
        set({ accessToken: token }),

      logout: () =>
        set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false }),

      hasPermission: (permission) => {
        const { user } = get()
        if (!user) return false
        const perms = ROLE_PERMISSIONS[user.role]
        return perms.includes('all') || perms.includes(permission)
      },
    }),
    {
      name: 'offensecops-auth',
      // Simpan SEMUA state — tidak ada partialState
      // isAuthenticated dan accessToken wajib persist agar tidak logout saat refresh
    }
  )
)
