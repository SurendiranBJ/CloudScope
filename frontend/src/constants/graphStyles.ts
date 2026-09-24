/**
 * CloudScope Canonical Graph Style & Color Palette
 *
 * Defines the single source of truth for visual styling, colors, and node shapes
 * across the Identity Graph and Attack Path DAG.
 */

export type CanonicalGraphType =
  | 'User'
  | 'Group'
  | 'Policy'
  | 'Role'
  | 'S3'
  | 'EC2'
  | 'Lambda'
  | 'RDS'
  | 'DynamoDB'
  | 'Secrets'
  | 'KMS'
  | 'APIGateway'
  | 'VPC'
  | 'Resource';

export interface EntityStyle {
  type: CanonicalGraphType;
  label: string;
  backgroundColor: string;
  borderColor: string;
  borderWidth?: string;
  shape: string;
  width: string;
  height: string;
  cardBgBorder: string;
  dotBg: string;
  badgeClass: string;
  textClass: string;
}

/**
 * Normalizes any entity/resource type variation (case differences, prefixes, singular/plural)
 * to its canonical graph entity type before color lookup.
 */
export const normalizeGraphType = (type?: string): CanonicalGraphType => {
  if (!type) return 'Resource';
  const clean = type.trim().toLowerCase();

  if (clean === 'user' || clean === 'iamuser' || clean === 'aws:user' || clean === 'users') return 'User';
  if (clean === 'group' || clean === 'iamgroup' || clean === 'aws:group' || clean === 'groups') return 'Group';
  if (clean === 'role' || clean === 'iamrole' || clean === 'aws:role' || clean === 'roles') return 'Role';
  if (clean === 'policy' || clean === 'iampolicy' || clean === 'aws:policy' || clean === 'policies') return 'Policy';
  if (clean === 's3' || clean === 's3bucket' || clean === 'bucket' || clean === 'aws:s3' || clean.includes('bucket')) return 'S3';
  if (clean === 'ec2' || clean === 'instance' || clean === 'ec2instance' || clean === 'aws:ec2' || clean.includes('ec2')) return 'EC2';
  if (clean === 'lambda' || clean === 'function' || clean === 'lambdafunction' || clean === 'aws:lambda' || clean.includes('lambda')) return 'Lambda';
  if (clean === 'rds' || clean === 'aurora' || clean === 'auroradbuser' || clean === 'database' || clean === 'rdbms' || clean === 'aws:rds' || clean.includes('rds') || clean.includes('aurora')) return 'RDS';
  if (clean === 'dynamodb' || clean === 'dynamo' || clean === 'table' || clean === 'dynamodbtable' || clean === 'aws:dynamodb' || clean.includes('dynamo')) return 'DynamoDB';
  if (clean === 'secret' || clean === 'secrets' || clean === 'secretsmanager' || clean === 'aws:secret' || clean === 'aws:secrets' || clean.includes('secret')) return 'Secrets';
  if (clean === 'kms' || clean === 'kmskey' || clean === 'key' || clean === 'aws:kms') return 'KMS';
  if (clean === 'apigateway' || clean === 'api' || clean === 'api_gateway' || clean === 'aws:apigateway') return 'APIGateway';
  if (clean === 'vpc' || clean === 'subnet' || clean === 'securitygroup' || clean === 'sg') return 'VPC';

  return 'Resource';
};

/**
 * Exact canonical colors and styles matching Identity Graph specification
 */
export const ENTITY_STYLES: Record<CanonicalGraphType, EntityStyle> = {
  User: {
    type: 'User',
    label: 'User',
    backgroundColor: '#3B82F6',
    borderColor: '#60A5FA',
    shape: 'ellipse',
    width: '42px',
    height: '42px',
    cardBgBorder: 'bg-blue-950/40 border-blue-500/50 text-blue-100 hover:border-blue-400',
    dotBg: '#3B82F6',
    badgeClass: 'bg-blue-950 text-blue-300 border-blue-500/40',
    textClass: 'text-blue-400'
  },
  Group: {
    type: 'Group',
    label: 'Group',
    backgroundColor: '#6366F1',
    borderColor: '#818CF8',
    borderWidth: '3px',
    shape: 'round-rectangle',
    width: '52px',
    height: '42px',
    cardBgBorder: 'bg-indigo-950/40 border-indigo-500/50 text-indigo-100 hover:border-indigo-400',
    dotBg: '#6366F1',
    badgeClass: 'bg-indigo-950 text-indigo-300 border-indigo-500/40',
    textClass: 'text-indigo-400'
  },
  Policy: {
    type: 'Policy',
    label: 'Policy',
    backgroundColor: '#14B8A6',
    borderColor: '#2DD4BF',
    shape: 'diamond',
    width: '42px',
    height: '42px',
    cardBgBorder: 'bg-teal-950/40 border-teal-500/50 text-teal-100 hover:border-teal-400',
    dotBg: '#14B8A6',
    badgeClass: 'bg-teal-950 text-teal-300 border-teal-500/40',
    textClass: 'text-teal-400'
  },
  Role: {
    type: 'Role',
    label: 'Role',
    backgroundColor: '#8B5CF6',
    borderColor: '#A78BFA',
    shape: 'hexagon',
    width: '46px',
    height: '46px',
    cardBgBorder: 'bg-purple-950/40 border-purple-500/50 text-purple-100 hover:border-purple-400',
    dotBg: '#8B5CF6',
    badgeClass: 'bg-purple-950 text-purple-300 border-purple-500/40',
    textClass: 'text-purple-400'
  },
  S3: {
    type: 'S3',
    label: 'S3',
    backgroundColor: '#F59E0B',
    borderColor: '#FBBF24',
    shape: 'barrel',
    width: '44px',
    height: '44px',
    cardBgBorder: 'bg-amber-950/40 border-amber-500/60 text-amber-100 hover:border-amber-400',
    dotBg: '#F59E0B',
    badgeClass: 'bg-amber-950 text-amber-300 border-amber-500/40',
    textClass: 'text-amber-400'
  },
  EC2: {
    type: 'EC2',
    label: 'EC2',
    backgroundColor: '#10B981',
    borderColor: '#34D399',
    shape: 'round-rectangle',
    width: '44px',
    height: '44px',
    cardBgBorder: 'bg-emerald-950/40 border-emerald-500/60 text-emerald-100 hover:border-emerald-400',
    dotBg: '#10B981',
    badgeClass: 'bg-emerald-950 text-emerald-300 border-emerald-500/40',
    textClass: 'text-emerald-400'
  },
  Lambda: {
    type: 'Lambda',
    label: 'Lambda',
    backgroundColor: '#EC4899',
    borderColor: '#F472B6',
    shape: 'ellipse',
    width: '42px',
    height: '42px',
    cardBgBorder: 'bg-pink-950/40 border-pink-500/60 text-pink-100 hover:border-pink-400',
    dotBg: '#EC4899',
    badgeClass: 'bg-pink-950 text-pink-300 border-pink-500/40',
    textClass: 'text-pink-400'
  },
  RDS: {
    type: 'RDS',
    label: 'RDS',
    backgroundColor: '#0EA5E9',
    borderColor: '#38BDF8',
    shape: 'round-rectangle',
    width: '46px',
    height: '44px',
    cardBgBorder: 'bg-sky-950/40 border-sky-500/60 text-sky-100 hover:border-sky-400',
    dotBg: '#0EA5E9',
    badgeClass: 'bg-sky-950 text-sky-300 border-sky-500/40',
    textClass: 'text-sky-400'
  },
  DynamoDB: {
    type: 'DynamoDB',
    label: 'DynamoDB',
    backgroundColor: '#A855F7',
    borderColor: '#C084FC',
    shape: 'round-rectangle',
    width: '44px',
    height: '44px',
    cardBgBorder: 'bg-violet-950/40 border-violet-500/60 text-violet-100 hover:border-violet-400',
    dotBg: '#A855F7',
    badgeClass: 'bg-violet-950 text-violet-300 border-violet-500/40',
    textClass: 'text-violet-400'
  },
  Secrets: {
    type: 'Secrets',
    label: 'Secrets',
    backgroundColor: '#EF4444',
    borderColor: '#F87171',
    borderWidth: '3px',
    shape: 'ellipse',
    width: '42px',
    height: '42px',
    cardBgBorder: 'bg-red-950/50 border-red-500/70 text-red-100 ring-1 ring-red-500/30 hover:border-red-400',
    dotBg: '#EF4444',
    badgeClass: 'bg-red-950 text-red-300 border-red-500/40',
    textClass: 'text-red-400'
  },
  KMS: {
    type: 'KMS',
    label: 'KMS',
    backgroundColor: '#EAB308',
    borderColor: '#FACC15',
    shape: 'diamond',
    width: '44px',
    height: '44px',
    cardBgBorder: 'bg-yellow-950/40 border-yellow-500/60 text-yellow-100 hover:border-yellow-400',
    dotBg: '#EAB308',
    badgeClass: 'bg-yellow-950 text-yellow-300 border-yellow-500/40',
    textClass: 'text-yellow-400'
  },
  APIGateway: {
    type: 'APIGateway',
    label: 'APIGateway',
    backgroundColor: '#F97316',
    borderColor: '#FB923C',
    shape: 'round-rectangle',
    width: '44px',
    height: '44px',
    cardBgBorder: 'bg-orange-950/40 border-orange-500/60 text-orange-100 hover:border-orange-400',
    dotBg: '#F97316',
    badgeClass: 'bg-orange-950 text-orange-300 border-orange-500/40',
    textClass: 'text-orange-400'
  },
  VPC: {
    type: 'VPC',
    label: 'VPC',
    backgroundColor: '#059669',
    borderColor: '#10B981',
    shape: 'round-rectangle',
    width: '44px',
    height: '44px',
    cardBgBorder: 'bg-emerald-950/40 border-emerald-600/60 text-emerald-100 hover:border-emerald-500',
    dotBg: '#059669',
    badgeClass: 'bg-emerald-950 text-emerald-300 border-emerald-500/40',
    textClass: 'text-emerald-400'
  },
  Resource: {
    type: 'Resource',
    label: 'Resource',
    backgroundColor: '#6B7280',
    borderColor: '#9CA3AF',
    shape: 'round-rectangle',
    width: '42px',
    height: '42px',
    cardBgBorder: 'bg-gray-900 border-gray-700 text-gray-200 hover:border-gray-500',
    dotBg: '#6B7280',
    badgeClass: 'bg-gray-800 text-gray-300 border-gray-600',
    textClass: 'text-gray-400'
  }
};

/**
 * Returns complete style information for any entity type.
 */
export const getGraphEntityStyle = (type?: string): EntityStyle => {
  const normalized = normalizeGraphType(type);
  return ENTITY_STYLES[normalized] || ENTITY_STYLES.Resource;
};

/**
 * Returns background and border hex colors for node rendering.
 */
export const getNodeColors = (type?: string): { background: string; border: string } => {
  const style = getGraphEntityStyle(type);
  return {
    background: style.backgroundColor,
    border: style.borderColor
  };
};

/**
 * Returns Tailwind CSS styling classes for target cards and badges.
 */
export const getTargetCardStyle = (type?: string) => {
  const style = getGraphEntityStyle(type);
  return {
    cardBgBorder: style.cardBgBorder,
    dotBg: style.dotBg,
    badgeClass: style.badgeClass,
    textClass: style.textClass
  };
};

/**
 * Canonical filter colors dictionary for toolbars and legends.
 */
export const CANONICAL_FILTER_COLORS: Record<string, string> = {
  User: ENTITY_STYLES.User.backgroundColor,
  Group: ENTITY_STYLES.Group.backgroundColor,
  Role: ENTITY_STYLES.Role.backgroundColor,
  Policy: ENTITY_STYLES.Policy.backgroundColor,
  S3: ENTITY_STYLES.S3.backgroundColor,
  EC2: ENTITY_STYLES.EC2.backgroundColor,
  Lambda: ENTITY_STYLES.Lambda.backgroundColor,
  RDS: ENTITY_STYLES.RDS.backgroundColor,
  DynamoDB: ENTITY_STYLES.DynamoDB.backgroundColor,
  Secrets: ENTITY_STYLES.Secrets.backgroundColor,
  Secret: ENTITY_STYLES.Secrets.backgroundColor,
  KMS: ENTITY_STYLES.KMS.backgroundColor,
  APIGateway: ENTITY_STYLES.APIGateway.backgroundColor,
  VPC: ENTITY_STYLES.VPC.backgroundColor
};
