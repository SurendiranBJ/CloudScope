import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('Reports Regression: getColor is declared before it is used to prevent ReferenceError', () => {
  const filePath = path.join(__dirname, '../src/pages/Reports.tsx');
  const code = fs.readFileSync(filePath, 'utf8');

  const getColorIndex = code.indexOf('const getColor =');
  const complianceStandardsIndex = code.indexOf('const complianceStandards =');

  assert.ok(getColorIndex > -1, 'getColor must exist');
  assert.ok(complianceStandardsIndex > -1, 'complianceStandards must exist');
  assert.ok(getColorIndex < complianceStandardsIndex, 'getColor must be declared before it is used in complianceStandards');
});
