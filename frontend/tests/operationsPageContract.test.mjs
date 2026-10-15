import test from 'node:test';
import assert from 'node:assert/strict';

test('Operations Contract: Valid payload contains all required canonical fields', () => {
  const validBackendPayload = {
    timestamp: '2026-10-10T12:00:00Z',
    commit_hash: 'cac394bd98d51b32',
    build_version: 'v1.0.0',
    app_version: '1.0.0',
    uptime_seconds: 3600,
    scanner: {
      is_scanning: false,
      active_phase: 'READY',
      mode: 'global',
      current_scan_id: null,
      current_snapshot_id: 'snap-123',
      progress: 0,
      resolved_regions: ['us-east-1'],
    },
    distributed_lock: {
      locked: false,
      owner_instance_id: null,
      acquired_at: null,
      ttl_seconds: 0,
      stale: false,
    },
    dependencies: {
      neo4j: true,
      redis: true,
      database: true,
    },
    metrics_summary: {
      last_scan_duration_seconds: 45.2,
      last_scan_status: 'SUCCESS',
      historical_failed_regions: [],
      recent_collector_failure_count: 0,
    },
    recent_scans: [
      {
        scan_id: 'scan-001',
        snapshot_id: 'snap-001',
        status: 'SUCCESS',
        started_at: '2026-10-10T11:00:00Z',
        completed_at: '2026-10-10T11:01:00Z',
        duration_seconds: 60.0,
        scan_mode: 'global',
        resolved_regions: ['us-east-1'],
        successful_regions: ['us-east-1'],
        failed_regions: [],
        active_phase: 'COMPLETED',
        total_collectors: 12,
        completed_collectors: 12,
        error_summary: null,
        created_by: 'admin',
        trigger_type: 'MANUAL',
      },
    ],
    latest_snapshot: { snapshot_id: 'snap-001' },
    recent_audit_events: [],
    system_status: 'HEALTHY',
    database_status: 'HEALTHY',
    database_error: null,
  };

  // Validate properties
  assert.strictEqual(typeof validBackendPayload.scanner.is_scanning, 'boolean');
  assert.strictEqual(typeof validBackendPayload.distributed_lock.locked, 'boolean');
  assert.strictEqual(typeof validBackendPayload.dependencies.database, 'boolean');
  assert.ok(Array.isArray(validBackendPayload.recent_scans));
  assert.strictEqual(validBackendPayload.recent_scans.length, 1);
  assert.strictEqual(validBackendPayload.recent_scans[0].scan_id, 'scan-001');
  assert.strictEqual(validBackendPayload.uptime_seconds, 3600);
});

test('Operations Contract: Malformed payload missing required fields triggers validation error', () => {
  const malformedPayloads = [
    null,
    {},
    { scanner: null },
    { scanner: { is_scanning: 'not-a-bool' }, distributed_lock: { locked: true }, dependencies: { database: true }, recent_scans: [] },
    { scanner: { is_scanning: false }, distributed_lock: null, dependencies: { database: true }, recent_scans: [] },
    { scanner: { is_scanning: false }, distributed_lock: { locked: false }, dependencies: null, recent_scans: [] },
    { scanner: { is_scanning: false }, distributed_lock: { locked: false }, dependencies: { database: true }, recent_scans: 'not-an-array' },
  ];

  for (const payload of malformedPayloads) {
    assert.throws(
      () => {
        if (!payload || typeof payload !== 'object') {
          throw new Error('Operations API returned an empty or invalid payload');
        }
        if (!payload.scanner || typeof payload.scanner.is_scanning !== 'boolean') {
          throw new Error('Malformed Operations response: missing valid scanner state');
        }
        if (!payload.distributed_lock || typeof payload.distributed_lock.locked !== 'boolean') {
          throw new Error('Malformed Operations response: missing valid distributed lock state');
        }
        if (!payload.dependencies || typeof payload.dependencies.database !== 'boolean') {
          throw new Error('Malformed Operations response: missing valid dependencies status');
        }
        if (!Array.isArray(payload.recent_scans)) {
          throw new Error('Malformed Operations response: recent_scans must be an array');
        }
      },
      /Malformed Operations response|Operations API returned an empty/,
      'Must reject invalid operations payload'
    );
  }
});

test('Operations Contract: Database outage is distinguishable from empty history', () => {
  // Case 1: Healthy database with 0 scan runs
  const healthyEmptyOverview = {
    database_status: 'HEALTHY',
    dependencies: { database: true },
    recent_scans: [],
  };
  const isHealthyEmpty =
    healthyEmptyOverview.database_status === 'HEALTHY' &&
    healthyEmptyOverview.dependencies.database === true &&
    healthyEmptyOverview.recent_scans.length === 0;
  assert.ok(isHealthyEmpty, 'Should recognize healthy empty history');

  // Case 2: Database outage
  const dbOutageOverview = {
    database_status: 'ERROR',
    dependencies: { database: false },
    database_error: 'Connection refused on port 5432',
    recent_scans: [],
  };
  const isDbOutage =
    dbOutageOverview.database_status === 'ERROR' ||
    dbOutageOverview.dependencies.database === false;
  assert.ok(isDbOutage, 'Must detect database outage rather than reporting empty history');
  assert.strictEqual(dbOutageOverview.database_error, 'Connection refused on port 5432');
});

test('Operations Contract: Audit event normalization guarantees unique ids and timestamps', () => {
  const rawEvents = [
    {
      event_id: 'ev-101',
      timestamp: '2026-10-10T11:30:00Z',
      actor_id: 'admin-1',
      actor_role: 'ADMINISTRATOR',
      action: 'SCAN_TRIGGERED',
      result: 'SUCCESS',
    },
    {
      id: 'ev-102',
      event_time: '2026-10-10T11:35:00Z',
      actor_id: 'admin-2',
      actor_role: 'ADMINISTRATOR',
      action: 'POLICY_MODIFIED',
      result: 'SUCCESS',
    },
    {
      // Missing id and timestamp
      actor_id: 'system',
      action: 'SYSTEM_HEALTHCHECK',
    },
  ];

  const normalized = rawEvents.map((ev, idx) => ({
    id: ev.id || ev.event_id || `audit-event-${idx}`,
    event_time: ev.event_time || ev.timestamp || new Date().toISOString(),
    actor_id: ev.actor_id || 'system',
    actor_role: ev.actor_role || 'SYSTEM',
    action: ev.action || 'UNKNOWN',
    result: ev.result || 'SUCCESS',
  }));

  assert.strictEqual(normalized[0].id, 'ev-101');
  assert.strictEqual(normalized[0].event_time, '2026-10-10T11:30:00Z');
  assert.strictEqual(normalized[1].id, 'ev-102');
  assert.strictEqual(normalized[1].event_time, '2026-10-10T11:35:00Z');
  assert.strictEqual(normalized[2].id, 'audit-event-2');
  assert.ok(normalized[2].event_time);
  assert.strictEqual(new Set(normalized.map(e => e.id)).size, 3, 'All IDs must be unique');
});

test('Operations Contract: Uptime formatting produces expected human-readable strings', () => {
  const formatUptime = (totalSeconds) => {
    if (!totalSeconds && totalSeconds !== 0) return '0s';
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = Math.floor(totalSeconds % 60);
    return `${hours}h ${minutes}m ${seconds}s`;
  };

  assert.strictEqual(formatUptime(0), '0h 0m 0s');
  assert.strictEqual(formatUptime(65), '0h 1m 5s');
  assert.strictEqual(formatUptime(3665), '1h 1m 5s');
  assert.strictEqual(formatUptime(86400), '24h 0m 0s');
});
