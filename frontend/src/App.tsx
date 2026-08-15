import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Sidebar } from './components/Sidebar';
import { Navbar } from './components/Navbar';
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

const queryClient = new QueryClient();

function App() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <div className="flex h-screen w-screen overflow-hidden bg-enterprise-bg text-gray-200">
          {/* Collapsible Left Sidebar */}
          <Sidebar collapsed={sidebarCollapsed} setCollapsed={setSidebarCollapsed} />

          {/* Right Main Content Column */}
          <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
            {/* Top Navigation */}
            <Navbar
              onSearchChange={setSearchQuery}
            />

            {/* Main Page Content Body */}
            <main className="flex-1 overflow-hidden flex flex-col">
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
              </Routes>
            </main>
          </div>
        </div>
      </Router>
    </QueryClientProvider>
  );
}

export default App;
