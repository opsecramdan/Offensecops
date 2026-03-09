import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './store/authStore'
import Layout from './components/layout/Layout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import TargetsPage from './pages/TargetsPage'
import ScansPage from './pages/ScansPage'
import SQLiPage from './pages/SQLiPage'
import VulnsPage from './pages/VulnsPage'
import VulnMgmtPage from './pages/VulnMgmtPage'
import ToolsPage from './pages/ToolsPage'
import ReportsPage from './pages/ReportsPage'
import AuditPage from './pages/AuditPage'
import UsersPage from './pages/UsersPage'
import AdvancedToolsPage from './pages/AdvancedToolsPage'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  return (
    <Routes>
      <Route
        path="/login"
        element={isAuthenticated ? <Navigate to="/" replace /> : <LoginPage />}
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="targets" element={<TargetsPage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="sqli" element={<SQLiPage />} />
        <Route path="vuln-mgmt" element={<VulnMgmtPage />} />
        <Route path="tools" element={<ToolsPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="users" element={<UsersPage />} />
            <Route path="advanced-tools" element={<AdvancedToolsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
