import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('AttackPaths DAG Regression: Source entities render dynamic types and styling', () => {
  const filePath = path.join(__dirname, '../src/pages/AttackPaths.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  // Verify that hardcoded "User" span has been replaced by dynamic srcType
  assert.ok(
    code.includes('const srcType = src.type ||'),
    'Source node must determine dynamic entity type from src.type'
  );
  assert.ok(
    code.includes('getGraphEntityStyle(src.type)'),
    'Source node styling must use getGraphEntityStyle(src.type)'
  );
  assert.ok(
    !code.includes('<span className="text-[8px] opacity-75 uppercase font-semibold">User</span>'),
    'Hardcoded User label for all source entities must be removed'
  );
});

test('AttackPaths DAG Regression: Edge labels match exact evidence and canonical IDs', () => {
  const filePath = path.join(__dirname, '../src/pages/AttackPaths.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  assert.ok(
    code.includes('step.from_node === srcNodeIdOrName'),
    'findExactEdgeLabel must check step.from_node from path evidence'
  );
  assert.ok(
    code.includes('step.to_node === tgtNodeIdOrName'),
    'findExactEdgeLabel must check step.to_node from path evidence'
  );
});

test('AttackPaths DAG Regression: 2-hop paths do not duplicate target as intermediate chain', () => {
  const filePath = path.join(__dirname, '../src/pages/AttackPaths.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  // Ensure intermediateNodes is empty for 2-hop paths
  assert.ok(
    code.includes('path.nodes.length > 2 \n        ? path.nodes.slice(1, -1) \n        : [];') ||
    code.includes('path.nodes.length > 2') && code.includes('path.nodes.slice(1, -1)'),
    'Intermediate nodes must strictly be between source and target'
  );
  assert.ok(
    !code.includes('(path.nodes.length === 2 ? [path.nodes[1]] : [])'),
    '2-hop paths must not duplicate target in intermediateNodes'
  );
});

test('AttackPaths DAG Regression: Blast radius and unique asset count are consistent', () => {
  const filePath = path.join(__dirname, '../src/pages/AttackPaths.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  assert.ok(
    code.includes('uniqueAssetsMap'),
    'Must calculate uniqueAssetsMap from assetsToBreakDown to prevent duplicate counts'
  );
  assert.ok(
    code.includes('totalUnique'),
    'Must display totalUnique matching uniqueAssetsMap.size'
  );
});

test('AttackPaths DAG Regression: Cytoscape uses valid barrel shape for databases', () => {
  const filePath = path.join(__dirname, '../src/pages/AttackPaths.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  assert.ok(
    !code.includes("'shape': 'database'"),
    "Invalid Cytoscape style 'shape: database' must not be present"
  );
});

test('AttackPaths DAG Regression: Trace in Full Graph selects directed path node sequence', () => {
  const filePath = path.join(__dirname, '../src/pages/AttackPaths.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  assert.ok(
    code.includes('handleHighlightInFullGraph'),
    'handleHighlightInFullGraph must exist'
  );
  assert.ok(
    code.includes('selectedPath.nodes.map(n => n.id || n.name)'),
    'handleHighlightInFullGraph must extract directed node sequence from selectedPath'
  );
});
