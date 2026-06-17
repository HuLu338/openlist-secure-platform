import { useEffect, useState } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { fetchHealth } from './api/api'
import Layout from './components/Layout'
import Alerts from './pages/Alerts'
import Analytics from './pages/Analytics'
import AuditLogs from './pages/AuditLogs'
import Dashboard from './pages/Dashboard'
import Events from './pages/Events'
import Policies from './pages/Policies'
import Recommendations from './pages/Recommendations'
import Rules from './pages/Rules'
import ScanHistory from './pages/ScanHistory'

const navItems = [
  { path: '/', label: 'Dashboard' },
  { path: '/scans', label: 'Scan History' },
  { path: '/events', label: 'Events' },
  { path: '/alerts', label: 'Alerts' },
  { path: '/rules', label: 'Rules' },
  { path: '/policies', label: 'Policies' },
  { path: '/recommendations', label: 'Recommendations' },
  { path: '/audit', label: 'API Audit Logs' },
  { path: '/analytics', label: 'Analytics' },
]

function App() {
  const location = useLocation()
  const [apiOnline, setApiOnline] = useState(false)
  const activePage = navItems.find((item) =>
    item.path === '/' ? location.pathname === '/' : location.pathname.startsWith(item.path),
  )

  async function checkAPIStatus() {
    try {
      await fetchHealth()
      setApiOnline(true)
    } catch {
      setApiOnline(false)
    }
  }

  useEffect(() => {
    checkAPIStatus()
    const timer = window.setInterval(checkAPIStatus, 30000)

    return () => {
      window.clearInterval(timer)
    }
  }, [])

  return (
    <Layout
      activeTitle={activePage?.label ?? 'OpenList Secure Platform'}
      apiOnline={apiOnline}
      navItems={navItems}
    >
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scans" element={<ScanHistory />} />
        <Route path="/events" element={<Events />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/recommendations" element={<Recommendations />} />
        <Route path="/audit" element={<AuditLogs />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/assistant" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}

export default App
