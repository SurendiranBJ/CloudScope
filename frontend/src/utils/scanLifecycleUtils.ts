import type { QueryClient } from '@tanstack/react-query';

export const SCAN_DEPENDENT_QUERY_KEYS = [
  ['dashboardSummary'],
  ['graphElements'],
  ['cloudResources'],
  ['resources'],
  ['attackPaths'],
  ['attack-paths'],
  ['riskAssessmentFindings'],
  ['securityFindings'],
  ['risks'],
  ['securityAlerts'],
  ['alerts'],
  ['iamUsers'],
  ['iam-users'],
  ['iamRoles'],
  ['iam-roles'],
  ['iamPolicies'],
  ['policies'],
  ['policy-catalog'],
  ['relationships'],
  ['entity-relationships'],
  ['reportsSummary'],
  ['reports'],
  ['effective-access'],
  ['scanStatus'],
];

export const PHASE_DESCRIPTIONS: Record<string, string> = {
  INITIALIZING: 'Authenticating AWS connection...',
  DISCOVERY: 'Collecting AWS inventory...',
  IAM_ANALYSIS: 'Evaluating IAM policies...',
  GRAPH_CONSTRUCTION: 'Building identity graph...',
  PATH_ANALYSIS: 'Analyzing attack paths...',
  CLOUDTRAIL_CORRELATION: 'Correlating CloudTrail activity...',
  FINDING_SYNTHESIS: 'Reconciling security findings...',
  PUBLISHING: 'Publishing security snapshot...',
  COMPLETED: 'Scan completed',
  FAILED: 'Scan failed',
  PARTIAL: 'Scan completed with regional failures',
};

export const getPhaseDescription = (
  phase?: string | null,
  scanStatus?: string,
  initStage?: string | null
): string => {
  const normPhase = (phase || '').toUpperCase();
  if (normPhase === 'INITIALIZING') {
    const stage = (initStage || '').toUpperCase();
    if (stage === 'AUTHENTICATING_AWS') return 'Authenticating AWS connection...';
    if (stage === 'RESOLVING_REGIONS') return 'Resolving AWS regions...';
    if (stage === 'STARTING_COLLECTORS') return 'Starting collectors...';
    return PHASE_DESCRIPTIONS.INITIALIZING;
  }
  if (!phase && !scanStatus) return 'Ready';
  if (PHASE_DESCRIPTIONS[normPhase]) {
    return PHASE_DESCRIPTIONS[normPhase];
  }
  const normStatus = (scanStatus || '').toUpperCase();
  if (normStatus === 'PARTIAL') return PHASE_DESCRIPTIONS.PARTIAL;
  if (normStatus === 'FAILED') return PHASE_DESCRIPTIONS.FAILED;
  if (normStatus === 'SUCCESS' || normStatus === 'COMPLETED') return PHASE_DESCRIPTIONS.COMPLETED;
  return normPhase ? normPhase.replace(/_/g, ' ') : 'Ready';
};

export const formatDuration = (seconds?: number): string => {
  if (seconds === undefined || seconds === null || isNaN(seconds)) return '00:00';
  const total = Math.max(0, Math.floor(seconds));
  const mins = Math.floor(total / 60);
  const secs = total % 60;
  return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
};

export const refreshScanDependentQueries = async (queryClient: QueryClient | { invalidateQueries: Function; refetchQueries?: Function }) => {
  for (const queryKey of SCAN_DEPENDENT_QUERY_KEYS) {
    try {
      if (typeof queryClient.refetchQueries === 'function') {
        await queryClient.refetchQueries({ queryKey, type: 'active' });
      } else {
        await queryClient.invalidateQueries({ queryKey });
      }
    } catch {
      await queryClient.invalidateQueries({ queryKey });
    }
  }
};
