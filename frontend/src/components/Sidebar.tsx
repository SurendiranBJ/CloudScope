import { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  LayoutDashboard,
  Cloud,
  Network,
  GitMerge,
  AlertTriangle,
  Bell,
  FileBarChart,
  Settings,
  ChevronLeft,
  ChevronRight,
  ShieldCheck
} from 'lucide-react';
import { apiClient } from '../api/client';

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, setCollapsed }) => {
  const [health, setHealth] = useState<{ commit: string; start_time: string } | null>(null);

  useEffect(() => {
    apiClient.get('/health')
      .then(res => {
        if (res.data && res.data.success) {
          setHealth(res.data.data);
        }
      })
      .catch(() => {});
  }, []);

  const menuItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Cloud Resources', path: '/resources', icon: Cloud },
    { name: 'Identity Graph', path: '/graph', icon: Network },
    { name: 'Attack Paths', path: '/attack-paths', icon: GitMerge },
    { name: 'Risk Assessment', path: '/risks', icon: AlertTriangle },
    { name: 'Alerts', path: '/alerts', icon: Bell },
    { name: 'Reports', path: '/reports', icon: FileBarChart },
    { name: 'Settings', path: '/settings', icon: Settings }
  ];

  return (
    <motion.div
      animate={{ width: collapsed ? '4.5rem' : '16rem' }}
      transition={{ duration: 0.3, ease: 'easeInOut' }}
      className="h-screen bg-enterprise-card border-r border-enterprise-border flex flex-col justify-between select-none relative z-50 shrink-0"
    >
      {/* Top Header */}
      <div>
        <div className="h-16 flex items-center justify-between px-4 border-b border-enterprise-border overflow-hidden">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-enterprise-accent flex items-center justify-center glow-blue shrink-0">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            {!collapsed && (
              <motion.span
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="font-bold text-lg bg-gradient-to-r from-white via-gray-200 to-enterprise-accent bg-clip-text text-transparent truncate"
              >
                IdentityScope
              </motion.span>
            )}
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="mt-4 px-2 space-y-1">
          {menuItems.map((item) => (
            <NavLink
              key={item.name}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? 'bg-enterprise-accent/15 text-enterprise-accent border-l-4 border-enterprise-accent'
                    : 'text-enterprise-subtext hover:bg-gray-800/50 hover:text-white'
                }`
              }
            >
              <div className="flex items-center gap-3 min-w-0">
                <item.icon className="w-5 h-5 shrink-0" />
                {!collapsed && (
                  <motion.span
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="truncate"
                  >
                    {item.name}
                  </motion.span>
                )}
              </div>
            </NavLink>
          ))}
        </nav>
      </div>

      {/* Health / Version Marker */}
      {health && (
        <div className="border-t border-enterprise-border">
          {!collapsed ? (
            <div className="px-4 py-2 text-[10px] text-enterprise-subtext font-mono">
              <div className="truncate">Backend: <span className="text-enterprise-accent font-semibold">{health.commit.substring(0, 7)}</span></div>
              <div className="mt-0.5 text-[9px] truncate" title={`Started: ${new Date(health.start_time).toLocaleString()}`}>
                Started: {new Date(health.start_time).toLocaleTimeString()}
              </div>
            </div>
          ) : (
            <div 
              className="py-2 text-center text-[10px] text-enterprise-accent font-mono cursor-default font-bold" 
              title={`Backend Commit: ${health.commit}\nStarted: ${new Date(health.start_time).toLocaleString()}`}
            >
              v:{health.commit.substring(0, 4)}
            </div>
          )}
        </div>
      )}

      {/* Collapse Toggle Footer Button */}
      <div className="p-3 border-t border-enterprise-border flex items-center justify-center">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full py-2 hover:bg-gray-800/50 rounded-lg text-enterprise-subtext hover:text-white transition-colors flex items-center justify-center"
        >
          {collapsed ? <ChevronRight className="w-5 h-5" /> : <ChevronLeft className="w-5 h-5" />}
        </button>
      </div>
    </motion.div>
  );
};
