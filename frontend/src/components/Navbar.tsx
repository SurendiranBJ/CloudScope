import React, { useState } from 'react';
import { Search, Bell, ChevronDown, User, Globe, AlertOctagon } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getDashboardSummary } from '../api/dashboard';

interface NavbarProps {
  onSearchChange?: (val: string) => void;
  selectedRegion: string;
  setSelectedRegion: (region: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onSearchChange,
  selectedRegion,
  setSelectedRegion
}) => {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfile, setShowProfile] = useState(false);

  const { data } = useQuery({
    queryKey: ['dashboardSummary'],
    queryFn: getDashboardSummary,
    refetchInterval: 10000
  });

  const alerts = data?.recentAlerts || [];

  const regions = [
    { code: 'ap-south-1', name: 'Asia Pacific (Mumbai)' },
    { code: 'us-east-1', name: 'US East (N. Virginia)' },
    { code: 'eu-west-1', name: 'Europe (Ireland)' }
  ];

  return (
    <header className="h-16 border-b border-enterprise-border bg-enterprise-card px-6 flex items-center justify-between relative z-40 select-none">
      {/* Search Input */}
      <div className="w-96 relative">
        <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Search className="h-4 w-4 text-enterprise-subtext" />
        </span>
        <input
          type="text"
          placeholder="Search IAM identities, resources, rules, alerts..."
          className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg pl-10 pr-4 py-2 text-sm text-white placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent transition-colors"
          onChange={(e) => onSearchChange && onSearchChange(e.target.value)}
        />
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* Region Selector */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-enterprise-border bg-enterprise-bg/40 text-sm text-gray-200">
          <Globe className="w-4 h-4 text-enterprise-accent" />
          <span className="font-semibold text-xs text-enterprise-subtext uppercase">Region:</span>
          <select
            value={selectedRegion}
            onChange={(e) => setSelectedRegion(e.target.value)}
            className="bg-transparent font-medium border-none focus:outline-none cursor-pointer text-white"
          >
            {regions.map((r) => (
              <option key={r.code} value={r.code} className="bg-enterprise-card text-white">
                {r.code} ({r.name.split(' ')[0]})
              </option>
            ))}
          </select>
        </div>

        {/* Notifications Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-2 text-enterprise-subtext hover:text-white rounded-lg hover:bg-gray-800/40 relative transition-colors"
          >
            <Bell className="w-5 h-5" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-enterprise-critical glow-red" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-enterprise-card border border-enterprise-border rounded-xl shadow-2xl glow-blue overflow-hidden z-50">
              <div className="p-3 border-b border-enterprise-border bg-enterprise-bg/40 flex justify-between items-center">
                <span className="font-semibold text-sm">Security Alerts</span>
                <span className="text-xs px-2 py-0.5 rounded bg-enterprise-critical/20 text-enterprise-critical font-bold">
                  {(alerts || []).length} Open
                </span>
              </div>
              <div className="divide-y divide-enterprise-border max-h-60 overflow-y-auto">
                {(alerts || []).map((alert: any) => (
                  <div key={alert.id} className="p-3 hover:bg-gray-800/20 transition-colors flex gap-2">
                    <AlertOctagon className={`w-5 h-5 shrink-0 ${alert.severity === 'critical' ? 'text-enterprise-critical' : 'text-enterprise-warning'}`} />
                    <div className="min-w-0">
                      <p className="text-xs font-semibold text-white truncate">{alert.description}</p>
                      <p className="text-[10px] text-enterprise-subtext mt-1">{alert.timestamp.split('T')[0]}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Profile Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowProfile(!showProfile)}
            className="flex items-center gap-2 p-1.5 hover:bg-gray-800/40 rounded-lg transition-colors border border-transparent hover:border-enterprise-border"
          >
            <div className="w-8 h-8 rounded-full bg-enterprise-accent/20 flex items-center justify-center border border-enterprise-accent/30 text-enterprise-accent">
              <User className="w-4 h-4" />
            </div>
            <div className="text-left hidden md:block">
              <p className="text-xs font-semibold text-white">Cloud Admin</p>
              <p className="text-[10px] text-enterprise-subtext">Security Officer</p>
            </div>
            <ChevronDown className="w-4 h-4 text-enterprise-subtext" />
          </button>

          {showProfile && (
            <div className="absolute right-0 mt-2 w-48 bg-enterprise-card border border-enterprise-border rounded-xl shadow-2xl overflow-hidden z-50 divide-y divide-enterprise-border">
              <div className="p-3">
                <p className="text-xs font-bold text-white">IdentityScope Sandbox</p>
                <p className="text-[10px] text-enterprise-subtext">admin@identityscope.io</p>
              </div>
              <div className="p-2 space-y-0.5">
                <button className="w-full text-left px-3 py-1.5 rounded hover:bg-gray-800 text-xs text-gray-200">
                  My Profile
                </button>
                <button className="w-full text-left px-3 py-1.5 rounded hover:bg-gray-800 text-xs text-gray-200">
                  Settings
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
