import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { apiClient, type APIResponse } from '../api/client';
import {
  LayoutDashboard,
  Cloud,
  GitMerge,
  AlertTriangle,
  Bell,
  FileBarChart,
  Settings,
  ChevronLeft,
  ChevronRight,
  Lock,
  ShieldCheck,
  Network,
  FolderKanban,
} from 'lucide-react';

interface ProjectOption { project_id: string; name: string; account_id: string | null; }

const fetchProjectOptions = async (): Promise<ProjectOption[]> => {
  const response = await apiClient.get<APIResponse<ProjectOption[]>>('/projects');
  return response.data.data;
};

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, setCollapsed }) => {
  const queryClient = useQueryClient();
  const [activeProjectId, setActiveProjectId] = useState(() => localStorage.getItem('cloudscope_project_id') || '');
  const projects = useQuery({ queryKey: ['projects'], queryFn: fetchProjectOptions });

  useEffect(() => {
    if (!projects.data?.length) {
      if (activeProjectId) {
        localStorage.removeItem('cloudscope_project_id');
        setActiveProjectId('');
        void queryClient.invalidateQueries();
      }
      return;
    }
    if (!projects.data.some((project) => project.project_id === activeProjectId)) {
      const nextProjectId = projects.data[0].project_id;
      localStorage.setItem('cloudscope_project_id', nextProjectId);
      setActiveProjectId(nextProjectId);
      void queryClient.invalidateQueries();
    }
  }, [projects.data, activeProjectId, queryClient]);

  const changeProject = (projectId: string) => {
    localStorage.setItem('cloudscope_project_id', projectId);
    setActiveProjectId(projectId);
    void queryClient.invalidateQueries();
  };

  const selectedProject = projects.data?.find((project) => project.project_id === activeProjectId);
  const menuItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Cloud Graph', path: '/graph', icon: Network },
    { name: 'Cloud Resources', path: '/resources', icon: Cloud },
    { name: 'Attack Paths', path: '/attack-paths', icon: GitMerge },
    { name: 'Security Findings', path: '/risks', icon: AlertTriangle },
    { name: 'Policies', path: '/policies', icon: Lock },
    { name: 'Projects', path: '/projects', icon: FolderKanban },
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
                CloudScope
              </motion.span>
            )}
          </div>
        </div>

        {projects.data && projects.data.length > 0 && (
          <div className={collapsed ? 'px-3 py-3 flex justify-center' : 'px-3 py-3'}>
            {collapsed ? (
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-enterprise-accent/10 text-enterprise-accent" title={selectedProject?.name || 'AWS project'}>
                <Cloud className="h-4 w-4" />
              </div>
            ) : (
              <label className="block">
                <span className="mb-1 block px-1 text-[10px] font-semibold uppercase tracking-wider text-enterprise-subtext">Active AWS project</span>
                <select
                  aria-label="Active AWS project"
                  value={activeProjectId}
                  onChange={(event) => changeProject(event.target.value)}
                  className="w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-2.5 py-2 text-xs text-enterprise-text outline-none focus:border-enterprise-accent"
                >
                  {projects.data.map((project) => (
                    <option key={project.project_id} value={project.project_id}>
                      {project.name}{project.account_id ? ` · ${project.account_id}` : ''}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
        )}

        {/* Navigation Items */}
        <nav className="mt-4 px-2 space-y-1">
          {menuItems.map((item) => (
            <NavLink
              key={item.name}
              to={item.path}
              end={item.path === '/'}
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
