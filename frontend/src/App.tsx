import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, Link } from 'react-router-dom'
import { DashboardEditor } from '@pages/DashboardEditor'
import DashboardList from './pages/DashboardList'
import { ESServersManager } from '@pages/ESServersManager'
import { ChatPage } from '@pages/ChatPage'
import { SettingsPage } from '@pages/SettingsPage'
import { LoginPage } from '@pages/LoginPage'
import SSOCallbackPage from '@pages/SSOCallbackPage'
import { ProfilePage } from '@pages/ProfilePage'
import { DownloadsPage } from '@pages/DownloadsPage'
import { CSVUploadPage } from '@pages/CSVUploadPage'
import { HomePage } from '@pages/HomePage'
import InfoPage from '@pages/InfoPage'
import DataLeaksPage from '@pages/DataLeaksPage'
import CVEPage from '@pages/CVEPage'
import CPFPage from '@pages/CPFPage'
import TelegramIntelligence from '@pages/TelegramIntelligence'
import TelegramConversation from '@pages/TelegramConversation'
import CTIDashboard from '@pages/cti/CTIDashboard'
import MISPFeedsPage from '@pages/cti/MISPFeedsPage'
import IOCEnrichmentPage from '@pages/cti/IOCEnrichmentPage'
import IOCSearchPage from '@pages/cti/IOCSearchPage'
import IOCBrowserPage from '@pages/cti/IOCBrowserPage'
import YARARulesPage from '@pages/cti/YARARulesPage'
import OTXPulsesPage from '@pages/cti/OTXPulsesPage'
import APTDashboard from '@pages/apt/APTDashboard'
import CredentialsPage from '@pages/CredentialsPage'
import DataLakePage from '@pages/DataLakePage'
import { Header } from './components/Header'
import { useDashboardStore } from '@stores/dashboardStore'
import { useSettingsStore } from '@stores/settingsStore'
import { useAuthStore } from '@stores/authStore'

// Protected Route Component
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuthStore()

  if (isLoading) {
    return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', width: '100vw', maxWidth: '100vw', overflow: 'hidden' }}>
      <div>Carregando...</div>
    </div>
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

// Admin-only Route Component
function AdminRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading, user } = useAuthStore()

  if (isLoading) {
    return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', width: '100vw', maxWidth: '100vw', overflow: 'hidden' }}>
      <div>Carregando...</div>
    </div>
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  if (!user?.can_configure_system) {
    return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', width: '100vw', maxWidth: '100vw', overflow: 'hidden', flexDirection: 'column', gap: '16px' }}>
      <div style={{ fontSize: '48px' }}>🔒</div>
      <div style={{ fontSize: '24px', fontWeight: '600' }}>Acesso Negado</div>
      <div style={{ fontSize: '14px', color: '#6b7280' }}>Você não tem permissão para acessar esta página.</div>
      <Link to="/" style={{ marginTop: '16px', padding: '8px 16px', backgroundColor: '#3b82f6', color: '#ffffff', borderRadius: '8px', textDecoration: 'none' }}>
        Voltar para Home
      </Link>
    </div>
  }

  return <>{children}</>
}

function App() {
  const initializeWebSocket = useDashboardStore((state) => state.initializeWebSocket)
  const disconnectWebSocket = useDashboardStore((state) => state.disconnectWebSocket)
  const { currentColors } = useSettingsStore()
  const { isAuthenticated } = useAuthStore()

  // Inicializar WebSocket quando app monta
  useEffect(() => {
    if (isAuthenticated) {
      initializeWebSocket()
    }

    // Cleanup: desconectar quando app desmonta
    return () => {
      disconnectWebSocket()
    }
  }, [isAuthenticated])

  return (
    <BrowserRouter>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100%', maxWidth: '100vw', overflow: 'hidden' }}>
        <Header />
        <main style={{ flex: 1, width: '100%', maxWidth: '100vw', overflow: 'hidden', minHeight: 0, height: '100%' }}>
          <Routes>
        {/* Login */}
        <Route path="/login" element={<LoginPage />} />

        {/* SSO Callback */}
        <Route path="/sso-callback" element={<SSOCallbackPage />} />

        {/* Home */}
        <Route path="/" element={
          <ProtectedRoute>
            <HomePage />
          </ProtectedRoute>
        } />

        {/* Dashboard List */}
        <Route path="/dashboards" element={<ProtectedRoute><DashboardList /></ProtectedRoute>} />

        {/* Dashboard Editor */}
        <Route path="/dashboard" element={<ProtectedRoute><DashboardEditor /></ProtectedRoute>} />

        {/* Chat Page */}
        <Route path="/chat" element={<ProtectedRoute><ChatPage /></ProtectedRoute>} />

        {/* Info Page (RSS Intelligence) */}
        <Route path="/info" element={<ProtectedRoute><InfoPage /></ProtectedRoute>} />

        {/* Data Leaks Page */}
        <Route path="/leaks" element={<ProtectedRoute><DataLeaksPage /></ProtectedRoute>} />

        {/* CVE Page */}
        <Route path="/cves" element={<ProtectedRoute><CVEPage /></ProtectedRoute>} />

        {/* CPF Page */}
        <Route path="/cpf" element={<ProtectedRoute><CPFPage /></ProtectedRoute>} />

        {/* Telegram Intelligence */}
        <Route path="/telegram" element={<ProtectedRoute><TelegramIntelligence /></ProtectedRoute>} />
        <Route path="/telegram/conversation" element={<ProtectedRoute><TelegramConversation /></ProtectedRoute>} />

        {/* Credentials Module */}
        <Route path="/credentials" element={<ProtectedRoute><CredentialsPage /></ProtectedRoute>} />
        <Route path="/datalake" element={<ProtectedRoute><DataLakePage /></ProtectedRoute>} />

        {/* APT Dashboard - Threat Actors Map */}
        <Route path="/apt" element={<ProtectedRoute><APTDashboard /></ProtectedRoute>} />

        {/* CTI Dashboard - IOC Intelligence */}
        <Route path="/cti" element={<ProtectedRoute><CTIDashboard /></ProtectedRoute>} />
        <Route path="/cti/feeds" element={<ProtectedRoute><MISPFeedsPage /></ProtectedRoute>} />
        <Route path="/cti/enrichment" element={<ProtectedRoute><IOCEnrichmentPage /></ProtectedRoute>} />
        <Route path="/cti/search" element={<ProtectedRoute><IOCSearchPage /></ProtectedRoute>} />
        <Route path="/cti/iocs" element={<ProtectedRoute><IOCBrowserPage /></ProtectedRoute>} />
        <Route path="/cti/yara" element={<ProtectedRoute><YARARulesPage /></ProtectedRoute>} />
        <Route path="/cti/pulses" element={<ProtectedRoute><OTXPulsesPage /></ProtectedRoute>} />

        {/* Profile Page */}
        <Route path="/profile" element={<ProtectedRoute><ProfilePage /></ProtectedRoute>} />

        {/* Downloads Page */}
        <Route path="/downloads" element={<ProtectedRoute><DownloadsPage /></ProtectedRoute>} />

        {/* CSV Upload Page */}
        <Route path="/csv-upload" element={<ProtectedRoute><CSVUploadPage /></ProtectedRoute>} />

        {/* ES Servers Manager */}
        <Route path="/servers" element={<AdminRoute><ESServersManager /></AdminRoute>} />

        {/* Settings */}
        <Route path="/settings" element={<AdminRoute><SettingsPage /></AdminRoute>} />

        {/* 404 */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App

