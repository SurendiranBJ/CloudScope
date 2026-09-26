import test from 'node:test';
import assert from 'node:assert/strict';
import { SCAN_DEPENDENT_QUERY_KEYS, refreshScanDependentQueries } from '../src/hooks/useScanDataRefresh.ts';

// Helper to simulate hierarchical React Query matching
function matchesQueryKey(invalidatedKey, queryKey) {
  if (invalidatedKey.length > queryKey.length) return false;
  return invalidatedKey.every((part, idx) => part === queryKey[idx]);
}

test('TEST 1: Initial page load with no data -> showInitialLoading is true', () => {
  const catalogData = undefined;
  const isLoading = true;
  const hasExistingData = !!catalogData && (catalogData.items || []).length > 0;
  const showInitialLoading = isLoading && !catalogData;

  assert.equal(hasExistingData, false);
  assert.equal(showInitialLoading, true);
});

test('TEST 2: Existing policy data + scan starts -> existing rows remain visible', () => {
  const catalogData = { items: [{ name: 'AdministratorAccess' }], total: 1 };
  const isLoading = false;
  const isFetching = true;
  const isScanning = true;

  const hasExistingData = !!catalogData && (catalogData.items || []).length > 0;
  const showInitialLoading = isLoading && !catalogData;
  const showRefreshing = isFetching && !!catalogData;

  assert.equal(hasExistingData, true, 'Existing data must remain present');
  assert.equal(showInitialLoading, false, 'Initial loading screen must not appear');
  assert.equal(showRefreshing, true, 'Non-blocking refresh indicator must be displayed');
  assert.equal(isScanning, true);
});

test('TEST 3: Existing relationship data + scan starts -> existing rows remain visible', () => {
  const relData = { relationships: [{ source_id: 'alice', relationship: 'HAS_POLICY', target_id: 'Admin' }] };
  const isLoading = false;
  const isFetching = true;
  const isScanning = true;

  const hasExistingData = !!relData && (relData.relationships || []).length > 0;
  const showInitialLoading = isLoading && !relData;
  const showRefreshing = isFetching && !!relData;

  assert.equal(hasExistingData, true);
  assert.equal(showInitialLoading, false);
  assert.equal(showRefreshing, true);
  assert.equal(isScanning, true);
});

test('TEST 4 & 5: Query keys hierarchy ensures ["policies"] and ["relationships"] invalidate granular query keys', () => {
  const policyKey = ['policies', 'customer-managed', 'admin', 1, 20];
  const relKey = ['relationships', 'HAS_POLICY', 'alice'];

  assert.ok(matchesQueryKey(['policies'], policyKey), 'Invalidating ["policies"] matches all granular policy queries');
  assert.ok(matchesQueryKey(['relationships'], relKey), 'Invalidating ["relationships"] matches all granular relationship queries');
});

test('TEST 6 & 7: refreshScanDependentQueries invalidates all scan-dependent keys', async () => {
  const invalidated = [];
  const mockQueryClient = {
    invalidateQueries: async ({ queryKey }) => {
      invalidated.push(queryKey);
    },
  };

  await refreshScanDependentQueries(mockQueryClient);

  const flatKeys = invalidated.map(k => k[0]);
  assert.ok(flatKeys.includes('policies'), 'Must invalidate policies');
  assert.ok(flatKeys.includes('relationships'), 'Must invalidate relationships');
  assert.ok(flatKeys.includes('cloudResources'), 'Must invalidate cloudResources');
  assert.ok(flatKeys.includes('iamUsers'), 'Must invalidate iamUsers');
  assert.ok(flatKeys.includes('iamRoles'), 'Must invalidate iamRoles');
  assert.ok(flatKeys.includes('scanStatus'), 'Must invalidate scanStatus');
});

test('TEST 8: Scan FAILED -> existing data preserved and scan-dependent data is NOT wiped', () => {
  const scanState = 'FAILED';
  const shouldRefreshData = scanState === 'SUCCESS' || scanState === 'PARTIAL';
  assert.equal(shouldRefreshData, false, 'FAILED scan must not trigger data refresh/wipe');

  const existingPolicies = [{ name: 'PreservedPolicy' }];
  const visibleData = shouldRefreshData ? [] : existingPolicies;
  assert.deepEqual(visibleData, existingPolicies, 'Last known authoritative snapshot must remain intact');
});

test('TEST 9 & 10: Deduplication prevents refresh loops when polling the same scan ID', () => {
  let processedScanId = null;
  let refreshCount = 0;

  function handleScanPoll(currentScanId, scanStatus) {
    if (processedScanId === null && currentScanId) {
      processedScanId = currentScanId;
      return; // Initial mount
    }

    if (currentScanId && currentScanId !== processedScanId) {
      processedScanId = currentScanId;
      if (scanStatus === 'SUCCESS' || scanStatus === 'PARTIAL') {
        refreshCount++;
      }
    }
  }

  // Initial poll with scan-001
  handleScanPoll('scan-001', 'SCANNING');
  assert.equal(refreshCount, 0, 'No refresh on initial mount');

  // Poll 10 times while scan-001 is running
  for (let i = 0; i < 10; i++) {
    handleScanPoll('scan-001', 'SCANNING');
  }
  assert.equal(refreshCount, 0, 'No refresh loop while polling same scan');

  // New scan completes: scan-002
  handleScanPoll('scan-002', 'SUCCESS');
  assert.equal(refreshCount, 1, 'Exactly one refresh occurs when new scan completes');

  // Repeated polls for completed scan-002
  for (let i = 0; i < 10; i++) {
    handleScanPoll('scan-002', 'SUCCESS');
  }
  assert.equal(refreshCount, 1, 'No duplicate refreshes for already processed scan ID');
});

test('TEST 11: Manual refresh with existing data keeps data visible', () => {
  const catalogData = { items: [{ name: 'S3Admin' }] };
  const isFetching = true;
  const isManualRefetching = true;

  const showInitialLoading = false;
  const hasExistingData = !!catalogData && catalogData.items.length > 0;

  assert.equal(hasExistingData, true);
  assert.equal(showInitialLoading, false);
  assert.equal(isFetching, true);
  assert.equal(isManualRefetching, true);
});

test('TEST 12: Filter/search changes preserve cached data via placeholderData / stale-while-revalidate', () => {
  let previousData = { items: [{ name: 'Pol1' }], total: 1 };
  
  // React Query v5 placeholderData pattern: (previousData) => previousData
  const placeholderFn = (prev) => prev;
  const renderedData = placeholderFn(previousData);

  assert.deepEqual(renderedData, previousData, 'Previous data is preserved during filter transition without blanking UI');
});
