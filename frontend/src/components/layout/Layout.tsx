import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import {
  LayoutDashboard, Target, Scan, Database, Shield, Wrench,
  FileText, ClipboardList, LogOut, Menu, X, ChevronRight, Users,
  Bell, User, Activity, Zap, Wrench as WrenchIcon
} from 'lucide-react'
import { useAuthStore } from '../../store/authStore'
import { api } from '../../lib/api'
import toast from 'react-hot-toast'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', exact: true },
  { to: '/targets', icon: Target, label: 'Targets' },
  { to: '/scans', icon: Scan, label: 'Scan Jobs' },
  { to: '/vuln-mgmt', icon: ClipboardList, label: 'Vuln Management' },
  { to: '/tools', icon: Wrench, label: 'Tool Registry' },
  { to: '/reports', icon: FileText, label: 'Reports' },
  { to: '/audit', icon: ClipboardList, label: 'Audit Log' },
  { to: '/advanced-tools', icon: Zap, label: 'Advanced Tools' },
  { to: '/users', icon: Users, label: 'Users' },
]

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()

  const handleLogout = async () => {
    try {
      await api.post('/auth/logout')
    } catch {}
    logout()
    navigate('/login')
    toast.success('Logged out successfully')
  }

  const getRoleColor = (role: string) => {
    const colors: Record<string, string> = {
      admin: 'text-severity-critical',
      manager: 'text-severity-medium',
      pentester: 'text-accent-primary',
      viewer: 'text-text-secondary',
      auditor: 'text-accent-info',
    }
    return colors[role] || 'text-text-secondary'
  }

  return (
    <div className="flex h-screen overflow-hidden cyber-bg">
      {/* Sidebar */}
      <aside
        className={`flex flex-col bg-bg-secondary border-r border-border-default transition-all duration-300 ${
          sidebarOpen ? 'w-64' : 'w-16'
        }`}
      >
        {/* Logo */}
        <div className="flex items-center h-16 px-4 border-b border-border-default">
          <div className="flex items-center gap-3 min-w-0">
            <div className="relative flex-shrink-0">
              <div className="w-8 h-8 bg-accent-primary rounded-md flex items-center justify-center">
                <Zap size={16} className="text-bg-primary" />
              </div>
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-severity-critical rounded-full border border-bg-secondary animate-pulse" />
            </div>
            {sidebarOpen && (
              <div className="overflow-hidden">
                <p className="font-display font-bold text-text-primary text-sm leading-none">OffenSecOps</p>
                <p className="text-text-muted text-xs font-mono mt-0.5">Red Team Platform</p>
              </div>
            )}
          </div>
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="ml-auto text-text-muted hover:text-text-primary transition-colors"
          >
            {sidebarOpen ? <X size={16} /> : <Menu size={16} />}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-4 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.exact}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 mx-2 rounded-md mb-1 transition-all duration-200 group ${
                  isActive
                    ? 'bg-accent-primary bg-opacity-10 text-accent-primary border border-accent-primary border-opacity-20'
                    : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <item.icon size={18} className={isActive ? 'text-accent-primary' : ''} />
                  {sidebarOpen && (
                    <>
                      <span className="text-sm font-medium flex-1">{item.label}</span>
                      {isActive && <ChevronRight size={14} className="text-accent-primary" />}
                    </>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* User Profile */}
        <div className="border-t border-border-default p-3">
          <div className={`flex items-center gap-3 ${sidebarOpen ? '' : 'justify-center'}`}>
            <div className="w-8 h-8 bg-bg-tertiary rounded-full border border-border-default flex items-center justify-center flex-shrink-0">
              <User size={14} className="text-text-secondary" />
            </div>
            {sidebarOpen && (
              <div className="flex-1 min-w-0">
                <p className="text-text-primary text-sm font-medium truncate">{user?.username}</p>
                <p className={`text-xs font-mono ${getRoleColor(user?.role || '')}`}>[{user?.role}]</p>
              </div>
            )}
            {sidebarOpen && (
              <button
                onClick={handleLogout}
                className="text-text-muted hover:text-severity-critical transition-colors"
                data-tooltip="Logout"
              >
                <LogOut size={16} />
              </button>
            )}
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Topbar */}
        <header className="h-16 bg-bg-secondary border-b border-border-default flex items-center px-6 gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 text-text-muted text-xs font-mono">
              <Activity size={12} className="text-accent-primary animate-pulse" />
              <span>System Status: </span>
              <span className="text-accent-primary">OPERATIONAL</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Notification Bell */}
            <button className="relative text-text-muted hover:text-text-primary transition-colors">
              <Bell size={18} />
              <span className="absolute -top-1 -right-1 w-4 h-4 bg-severity-critical rounded-full text-xs flex items-center justify-center text-white font-bold">
                3
              </span>
            </button>

            {/* IP indicator */}
            <div className="bg-bg-tertiary border border-border-default rounded px-3 py-1.5 font-mono text-xs text-text-secondary">
              10.16.91.126
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
