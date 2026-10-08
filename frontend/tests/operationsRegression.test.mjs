import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('Operations Regression: Overview uses optional chaining to prevent crashes on partial data', () => {
  const filePath = path.join(__dirname, '../src/pages/Operations.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  // Verify that we are using optional chaining for nested properties of overview
  assert.ok(code.includes('overview?.'), 'Must use optional chaining for overview properties to prevent crashes on partial loading states');
});
