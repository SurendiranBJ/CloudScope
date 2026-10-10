import { lazy, Suspense, useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ScanLifecycleProvider } from './context/ScanLifecycleContext.tsx';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import { Sidebar } from './components/Sidebar';
import { Navbar } from './components/Navbar';
import { SimulationBanner } from './components/SimulationBanner';
import { SecurityNoticeBanner } from './components/SecurityNoticeBanner';
import { ProtectedRoute } from './components/ProtectedRoute';
import { ErrorBoundary } from './components/ErrorBoundary';

const Dashboard = lazy(async () => ({ default: (await import('./pages/Dashboard')).Dashboard }));
const Resources = lazy(async () => ({ default: (await import('./pages/Resources')).Resources }));
const IdentityGraphPage = lazy(async () => ({ default: (await import('./pages/IdentityGraphPage')).IdentityGraphPage }));
const AttackPaths = lazy(async () => ({ default: (await import('./pages/AttackPaths')).AttackPaths }));
const RiskAssessment = lazy(async () => ({ default: (await import('./pages/RiskAssessment')).RiskAssessment }));
const AttackSimulation = lazy(async () => ({ default: (await import('./pages/AttackSimulation')).AttackSimulation }));
const Alerts = lazy(async () => ({ default: (await import('./pages/Alerts')).Alerts }));
const Copilot = lazy(async () => ({ default: (await import('./pages/Copilot')).Copilot }));
const Reports = lazy(async () => ({ default: (await import('./pages/Reports')).Reports }));
const SettingsPage = lazy(async () => ({ default: (await import('./pages/Settings')).SettingsPage }));
const Policies = lazy(async () => ({ default: (await import('./pages/Policies')).Policies }));
const Relationships = lazy(async () => ({ default: (await import('./pages/Relationships')).Relationships }));
const Changes = lazy(async () => ({ default: (await import('./pages/Changes')).Changes }));
const Operations = lazy(async () => ({ default: (await import('./pages/Operations')).Operations }));
const Forbidden = lazy(async () => ({ default: (await import('./pages/Forbidden')).Forbidden }));

const queryClient = new QueryClient();

function App() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <ScanLifecycleProvider>
            <Router>
              <div className="flex h-screen w-screen overflow-hidden bg-enterprise-bg text-enterprise-text transition-colors duration-200">
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
                  <Suspense fallback={<div className="flex flex-1 items-center justify-center text-sm text-enterprise-subtext" role="status">Loading view…</div>}>
                  <ErrorBoundary>
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
                  </ErrorBoundary>
                  </Suspense>
                </main>
              </div>
            </div>
          </Router>
        </ScanLifecycleProvider>
      </AuthProvider>
    </ThemeProvider>
  </QueryClientProvider>
  );
}

export default App;
