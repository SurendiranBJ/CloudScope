import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('Identity Graph Regression: Callbacks are wrapped in useCallback to prevent child re-renders', () => {
  const filePath = path.join(__dirname, '../src/pages/IdentityGraphPage.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  assert.ok(code.includes('const handleNodeSelect = useCallback'), 'handleNodeSelect must use useCallback');
  assert.ok(code.includes('const handleEdgeSelect = useCallback'), 'handleEdgeSelect must use useCallback');
  assert.ok(code.includes('const handleClearFocus = useCallback'), 'handleClearFocus must use useCallback');
});

test('Identity Graph Regression: Toolbar layout-breaking filters are removed', () => {
  const filePath = path.join(__dirname, '../src/pages/IdentityGraphPage.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  assert.ok(!code.includes('setFocusDepth'), 'Focus Depth control must be removed to prevent layout issues');
  assert.ok(!code.includes('setSecurityFilter'), 'Security Filter control must be removed to prevent edge disconnection');
});

test('Identity Graph Regression: showLabels and showEdgeLabels are handled dynamically via cy.style updates', () => {
  const filePath = path.join(__dirname, '../src/components/IdentityGraph.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  assert.ok(code.includes('cy.style()'), 'Must use cy.style() to update styles dynamically');
  assert.ok(code.includes('showLabels ?'), 'Must check showLabels dynamically');
  
  // Verify that the initialization useEffect does not depend on showLabels or showEdgeLabels
  const useEffectBlock = code.match(/cy\.destroy\(\);\s*cyRef\.current = null;\s*\}\s*;\s*\}, \[(.*?)\]\);/);
  if (useEffectBlock) {
    const deps = useEffectBlock[1];
    assert.ok(!deps.includes('showLabels'), 'Initialization useEffect must not depend on showLabels to avoid Cytoscape re-creation');
    assert.ok(!deps.includes('showEdgeLabels'), 'Initialization useEffect must not depend on showEdgeLabels to avoid Cytoscape re-creation');
  } else {
    assert.fail('Could not parse initialization useEffect dependencies');
  }
});
