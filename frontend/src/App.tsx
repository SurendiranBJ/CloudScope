import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ScanLifecycleProvider } from './context/ScanLifecycleContext.tsx';
import { AuthProvider } from './context/AuthContext';
import { Sidebar } from './components/Sidebar';
import { Navbar } from './components/Navbar';
import { SimulationBanner } from './components/SimulationBanner';
import { SecurityNoticeBanner } from './components/SecurityNoticeBanner';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Dashboard } from './pages/Dashboard';
import { Resources } from './pages/Resources';
import { IdentityGraphPage } from './pages/IdentityGraphPage';
import { AttackPaths } from './pages/AttackPaths';
import { RiskAssessment } from './pages/RiskAssessment';
import { AttackSimulation } from './pages/AttackSimulation';
import { Alerts } from './pages/Alerts';
import { Copilot } from './pages/Copilot';
import { Reports } from './pages/Reports';
import { SettingsPage } from './pages/Settings';
import { Policies } from './pages/Policies';
import { Relationships } from './pages/Relationships';
import { Changes } from './pages/Changes';
import { Operations } from './pages/Operations';
import { Forbidden } from './pages/Forbidden';

const queryClient = new QueryClient();

function App() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ScanLifecycleProvider>
          <Router>
            <div className="flex h-screen w-screen overflow-hidden bg-enterprise-bg text-gray-200">
              {/* Collapsible Left Sidebar */}
              <Sidebar collapsed={sidebarCollapsed} setCollapsed={setSidebarCollapsed} />

              {/* Right Main Content Column */}
              <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
                {/* Top Navigation */}
                <Navbar onSearchChange={setSearchQuery} />

                {/* Global Security Notices (Rate limit countdown, 403 alerts, 500 error request_id) */}
                <SecurityNoticeBanner />

                {/* Main Page Content Body */}
                <main className="flex-1 min-h-0 overflow-hidden flex flex-col">
                  {/* Simulation active banner */}
                  <SimulationBanner />
                  <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/resources" element={<Resources search={searchQuery} />} />
                    <Route path="/graph" element={<IdentityGraphPage />} />
                    <Route path="/attack-paths" element={<AttackPaths />} />
                    <Route path="/risks" element={<RiskAssessment search={searchQuery} />} />
                    <Route path="/simulation" element={<AttackSimulation />} />
                    <Route path="/alerts" element={<Alerts />} />
                    <Route path="/copilot" element={<Copilot />} />
                    <Route path="/reports" element={<Reports />} />
                    <Route path="/settings" element={<SettingsPage />} />
                    <Route path="/policies" element={<Policies />} />
                    <Route path="/relationships" element={<Relationships />} />
                    <Route path="/changes" element={<Changes />} />
                    <Route
                      path="/operations"
                      element={
                        <ProtectedRoute minRole="ADMINISTRATOR">
                          <Operations />
                        </ProtectedRoute>
                      }
                    />
                    <Route path="/forbidden" element={<Forbidden />} />
                  </Routes>
                </main>
              </div>
            </div>
          </Router>
        </ScanLifecycleProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
