import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('Reports Regression: exports assessment data without audit or control-coverage reports', () => {
  const filePath = path.join(__dirname, '../src/pages/Reports.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  assert.ok(code.includes("id: 'json', title: 'Security Assessment Data'"));
  assert.ok(code.includes("id: 'svg', title: 'Identity Graph Architecture'"));
  assert.ok(code.includes('Overall Platform Summary'));
  assert.ok(!code.includes('Security Audit Summary'));
  assert.ok(!code.includes('Security Control Coverage'));
  assert.ok(!code.includes('controlCoverage:'));
});
