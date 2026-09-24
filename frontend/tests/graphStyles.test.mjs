import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeGraphType,
  getGraphEntityStyle,
  getNodeColors,
  getTargetCardStyle,
  ENTITY_STYLES,
} from '../src/constants/graphStyles.ts';

test('normalizeGraphType handles canonical and case variations', () => {
  // Lambda variations
  assert.equal(normalizeGraphType('Lambda'), 'Lambda');
  assert.equal(normalizeGraphType('LAMBDA'), 'Lambda');
  assert.equal(normalizeGraphType('lambda'), 'Lambda');

  // EC2 variations
  assert.equal(normalizeGraphType('EC2'), 'EC2');
  assert.equal(normalizeGraphType('ec2'), 'EC2');
  assert.equal(normalizeGraphType('Ec2'), 'EC2');

  // S3 variations
  assert.equal(normalizeGraphType('S3'), 'S3');
  assert.equal(normalizeGraphType('s3'), 'S3');

  // Secrets variations
  assert.equal(normalizeGraphType('Secrets'), 'Secrets');
  assert.equal(normalizeGraphType('Secret'), 'Secrets');
  assert.equal(normalizeGraphType('SECRETS'), 'Secrets');
  assert.equal(normalizeGraphType('SECRET'), 'Secrets');

  // RDS variations
  assert.equal(normalizeGraphType('RDS'), 'RDS');
  assert.equal(normalizeGraphType('rds'), 'RDS');

  // DynamoDB variations
  assert.equal(normalizeGraphType('DynamoDB'), 'DynamoDB');
  assert.equal(normalizeGraphType('dynamodb'), 'DynamoDB');
  assert.equal(normalizeGraphType('DYNAMODB'), 'DynamoDB');

  // Other entities
  assert.equal(normalizeGraphType('User'), 'User');
  assert.equal(normalizeGraphType('user'), 'User');
  assert.equal(normalizeGraphType('Group'), 'Group');
  assert.equal(normalizeGraphType('group'), 'Group');
  assert.equal(normalizeGraphType('Policy'), 'Policy');
  assert.equal(normalizeGraphType('Role'), 'Role');
  assert.equal(normalizeGraphType('role'), 'Role');
  assert.equal(normalizeGraphType('KMS'), 'KMS');
  assert.equal(normalizeGraphType('kms'), 'KMS');
  assert.equal(normalizeGraphType('APIGateway'), 'APIGateway');
  assert.equal(normalizeGraphType('API'), 'APIGateway');
});

test('Color lookup returns exact canonical colors without amber fallback for supported types', () => {
  // EC2 is emerald #10B981
  const ec2Style = getGraphEntityStyle('ec2');
  assert.equal(ec2Style.backgroundColor, '#10B981');
  assert.equal(ec2Style.borderColor, '#34D399');

  // Lambda is pink #EC4899
  const lambdaStyle = getGraphEntityStyle('LAMBDA');
  assert.equal(lambdaStyle.backgroundColor, '#EC4899');
  assert.equal(lambdaStyle.borderColor, '#F472B6');

  // S3 is amber #F59E0B
  const s3Style = getGraphEntityStyle('s3');
  assert.equal(s3Style.backgroundColor, '#F59E0B');
  assert.equal(s3Style.borderColor, '#FBBF24');

  // RDS is sky #0EA5E9
  const rdsStyle = getGraphEntityStyle('RDS');
  assert.equal(rdsStyle.backgroundColor, '#0EA5E9');
  assert.equal(rdsStyle.borderColor, '#38BDF8');

  // DynamoDB is violet #A855F7 (NOT cyan)
  const dynamoStyle = getGraphEntityStyle('dynamodb');
  assert.equal(dynamoStyle.backgroundColor, '#A855F7');
  assert.equal(dynamoStyle.borderColor, '#C084FC');

  // Secrets is red #EF4444
  const secretsStyle = getGraphEntityStyle('Secret');
  assert.equal(secretsStyle.backgroundColor, '#EF4444');
  assert.equal(secretsStyle.borderColor, '#F87171');

  // Role is purple #8B5CF6
  const roleStyle = getGraphEntityStyle('role');
  assert.equal(roleStyle.backgroundColor, '#8B5CF6');
  assert.equal(roleStyle.borderColor, '#A78BFA');

  // getNodeColors helper test
  const nodeColors = getNodeColors('ec2');
  assert.equal(nodeColors.background, '#10B981');
  assert.equal(nodeColors.border, '#34D399');
});

test('getTargetCardStyle produces valid CSS card styling for all target types', () => {
  const targetTypes = ['S3', 'EC2', 'Lambda', 'RDS', 'DynamoDB', 'Secrets', 'Role'];
  const colorsSeen = new Set();

  for (const t of targetTypes) {
    const cardStyle = getTargetCardStyle(t);
    assert.ok(cardStyle.cardBgBorder.length > 0, `cardBgBorder defined for ${t}`);
    assert.ok(cardStyle.dotBg.length > 0, `dotBg defined for ${t}`);
    assert.ok(cardStyle.badgeClass.length > 0, `badgeClass defined for ${t}`);
    assert.ok(cardStyle.textClass.length > 0, `textClass defined for ${t}`);
    colorsSeen.add(cardStyle.dotBg);
  }

  // All 7 target types must have distinct dot colors (no generic amber fallback)
  assert.equal(colorsSeen.size, 7, 'All target types must have unique dot colors');
});
