import type { SecurityFinding } from '../types';

const SEVERITY_LEVELS = [
  { name: 'Critical', color: '#EF4444' },
  { name: 'High', color: '#F59E0B' },
  { name: 'Medium', color: '#3B82F6' },
  { name: 'Low', color: '#10B981' },
] as const;

export const summarizeDashboardFindings = (findings?: SecurityFinding[]) => {
  const activeFindings = (findings || []).filter((finding) => {
    const source = String(finding.source || '').toUpperCase();
    const type = String(finding.type || '').toUpperCase();
    return String(finding.status || 'OPEN').toUpperCase() === 'OPEN'
      && source !== 'ATTACK_PATH'
      && type !== 'ATTACK_PATH_VULNERABILITY';
  });

  return {
    activeFindingCount: activeFindings.length,
    riskDistribution: SEVERITY_LEVELS.map(({ name, color }) => ({
      name,
      color,
      value: activeFindings.filter((finding) => String(finding.severity || '').toLowerCase() === name.toLowerCase()).length,
    })),
  };
};
