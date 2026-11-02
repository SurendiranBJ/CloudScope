import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeDashboardFindings } from '../src/utils/dashboardMetrics.ts';

test('Dashboard finding cards and severity chart exclude attack-path-only and closed findings', () => {
  const summary = summarizeDashboardFindings([
    { id: 'iam-1', status: 'OPEN', source: 'STATIC_IAM', type: 'WILDCARD_POLICY', severity: 'high' },
    { id: 'resource-1', status: 'OPEN', source: 'RESOURCE_CONFIGURATION', type: 'PUBLIC_RESOURCE', severity: 'critical' },
    { id: 'path-1', status: 'OPEN', source: 'ATTACK_PATH', type: 'ATTACK_PATH_VULNERABILITY', severity: 'critical' },
    { id: 'closed-1', status: 'RESOLVED', source: 'STATIC_IAM', type: 'OLD_POLICY', severity: 'medium' },
  ]);

  assert.equal(summary.activeFindingCount, 2);
  assert.deepEqual(summary.riskDistribution.map(({ name, value }) => ({ name, value })), [
    { name: 'Critical', value: 1 },
    { name: 'High', value: 1 },
    { name: 'Medium', value: 0 },
    { name: 'Low', value: 0 },
  ]);
});
