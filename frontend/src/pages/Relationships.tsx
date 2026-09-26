import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, Network, GitMerge, ChevronRight, RefreshCw,
  User, Shield, Database, Cloud, Users, ArrowRight, Filter, X, AlertTriangle, CheckCircle
} from 'lucide-react';
import { getRelationships, getEntityRelationships } from '../api/relationships';
import { useScanDataRefresh } from '../hooks/useScanDataRefresh';
import type { RelationshipEntry } from '../types';

const REL_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  MEMBER_OF:      { bg: 'bg-purple-500/10', text: 'text-purple-400',  border: 'border-purple-500/25' },
  HAS_POLICY:     { bg: 'bg-blue-500/10',   text: 'text-blue-400',    border: 'border-blue-500/25' },
  CAN_ASSUME:     { bg: 'bg-amber-500/10',  text: 'text-amber-400',   border: 'border-amber-500/25' },
  ALLOWS:         { bg: 'bg-green-500/10',  text: 'text-green-400',   border: 'border-green-500/25' },
  TRUSTS:         { bg: 'bg-cyan-500/10',   text: 'text-cyan-400',    border: 'border-cyan-500/25' },
  ATTACHED_TO:    { bg: 'bg-indigo-500/10', text: 'text-indigo-400',  border: 'border-indigo-500/25' },
  EXECUTES_WITH:  { bg: 'bg-pink-500/10',   text: 'text-pink-400',    border: 'border-pink-500/25' },
  DENIES:         { bg: 'bg-red-500/10',    text: 'text-red-400',     border: 'border-red-500/25' },
  UNKNOWN:        { bg: 'bg-gray-500/10',   text: 'text-gray-400',    border: 'border-gray-500/25' },
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
  User:   <User className="w-3.5 h-3.5 text-blue-400" />,
  Role:   <Shield className="w-3.5 h-3.5 text-amber-400" />,
  Group:  <Users className="w-3.5 h-3.5 text-purple-400" />,
  Policy: <GitMerge className="w-3.5 h-3.5 text-green-400" />,
  S3:     <Database className="w-3.5 h-3.5 text-cyan-400" />,
  EC2:    <Cloud className="w-3.5 h-3.5 text-orange-400" />,
  Lambda: <Cloud className="w-3.5 h-3.5 text-yellow-400" />,
  RDS:    <Database className="w-3.5 h-3.5 text-indigo-400" />,
  DynamoDB: <Database className="w-3.5 h-3.5 text-pink-400" />,
  Secrets: <Shield className="w-3.5 h-3.5 text-red-400" />,
};

function RelBadge({ rel }: { rel: string }) {
  const c = REL_COLORS[rel] ?? REL_COLORS.UNKNOWN;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wide border ${c.bg} ${c.text} ${c.border}`}>
      {rel}
    </span>
  );
}

function EntityIcon({ type }: { type: string }) {
  return TYPE_ICONS[type] ?? <Network className="w-3.5 h-3.5 text-gray-400" />;
}

type FilterType = 'all' | 'User' | 'Role' | 'Group' | 'Policy';

export const Relationships: React.FC = () => {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<FilterType>('all');
  const [selectedEntity, setSelectedEntity] = useState<string | null>(null);
  const [relFilter, setRelFilter] = useState<string>('all');

  const {
    isScanning,
    scanJustCompleted,
    isPartial,
    isFailed,
    lastCompletedAt,
    hasCompletedSnapshot,
  } = useScanDataRefresh();

  const { data: relData, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey: ['relationships', typeFilter, search],
    queryFn: () => getRelationships({
      entity_type: typeFilter === 'all' ? undefined : typeFilter,
      search: search || undefined,
      limit: 1000,
    }),
    staleTime: 30_000,
    placeholderData: (previousData) => previousData,
  });

  const { data: entityData } = useQuery({
    queryKey: ['entity-relationships', selectedEntity],
    queryFn: () => selectedEntity ? getEntityRelationships(selectedEntity) : Promise.resolve(null),
    enabled: !!selectedEntity,
  });

  const allRels = relData?.relationships ?? [];
  const hasExistingData = !!relData && allRels.length > 0;
  const showInitialLoading = isLoading && !relData && !hasCompletedSnapshot;

  const uniqueRelTypes = useMemo(() => {
    const s = new Set(allRels.map(r => r.relationship));
    return ['all', ...Array.from(s).sort()];
  }, [allRels]);

  const filtered = useMemo(() => {
    return allRels.filter(r => relFilter === 'all' || r.relationship === relFilter);
  }, [allRels, relFilter]);

  // Group by source entity
  const grouped = useMemo(() => {
    const map = new Map<string, RelationshipEntry[]>();
    for (const r of filtered) {
      const key = r.source_id;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(r);
    }
    return Array.from(map.entries()).map(([sourceId, rels]) => ({
      sourceId,
      sourceLabel: rels[0].source_label,
      sourceType: rels[0].source_type,
      rels,
    }));
  }, [filtered]);

  const filterTabs: { label: string; value: FilterType }[] = [
    { label: 'All', value: 'all' },
    { label: 'Users', value: 'User' },
    { label: 'Roles', value: 'Role' },
    { label: 'Groups', value: 'Group' },
    { label: 'Policies', value: 'Policy' },
  ];

  return (
    <div className="flex h-full overflow-hidden">
      {/* Main relationship browser */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        {/* Header */}
        <div className="shrink-0 px-6 py-4 border-b border-enterprise-border">
          <div className="flex items-center justify-between gap-4 mb-4">
            <div>
              <h1 className="text-xl font-bold text-white flex items-center gap-2">
                <Network className="w-5 h-5 text-enterprise-accent" />
                Identity Relationships
              </h1>
              <div className="flex flex-wrap items-center gap-2 mt-0.5">
                <p className="text-xs text-enterprise-subtext">
                  All IAM relationships from real AWS discovery — no inferred labels
                </p>
                {isScanning && (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/25 text-blue-400 text-[11px] animate-pulse">
                    <RefreshCw className="w-3 h-3 animate-spin text-blue-400" />
                    Updating relationships from latest AWS scan...
                  </span>
                )}
                {scanJustCompleted && (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-green-500/10 border border-green-500/25 text-green-400 text-[11px]">
                    <CheckCircle className="w-3 h-3 text-green-400" />
                    Relationships updated
                  </span>
                )}
                {isPartial && !isScanning && !scanJustCompleted && (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/25 text-amber-400 text-[11px]">
                    <AlertTriangle className="w-3 h-3 text-amber-400" />
                    Updated from a partial AWS scan. Some regions were unavailable.
                  </span>
                )}
                {isFailed && !isScanning && (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/25 text-red-400 text-[11px]">
                    <AlertTriangle className="w-3 h-3 text-red-400" />
                    Latest scan failed. Showing the last completed snapshot{lastCompletedAt ? ` (${new Date(lastCompletedAt).toLocaleTimeString()})` : ''}.
                  </span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {relData && (
                <div className="text-xs text-enterprise-subtext">
                  {relData.total.toLocaleString()} relationship{relData.total !== 1 ? 's' : ''}
                </div>
              )}
              <button
                onClick={() => refetch()}
                disabled={isFetching}
                title="Refresh relationships"
                className="p-2 rounded-lg border border-enterprise-border hover:bg-gray-800/50 text-enterprise-subtext hover:text-white transition-colors disabled:opacity-60"
              >
                <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin text-enterprise-accent' : ''}`} />
              </button>
            </div>
          </div>

          {/* Search */}
          <div className="relative mb-3">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-enterprise-subtext" />
            <input
              id="rel-search"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search by entity name..."
              className="w-full pl-9 pr-4 py-2 bg-enterprise-card border border-enterprise-border rounded-lg text-sm text-gray-200 placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent"
            />
          </div>

          <div className="flex items-center gap-4">
            {/* Entity type filter */}
            <div className="flex gap-1">
              {filterTabs.map(t => (
                <button
                  key={t.value}
                  onClick={() => setTypeFilter(t.value)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    typeFilter === t.value
                      ? 'bg-enterprise-accent/15 text-enterprise-accent border border-enterprise-accent/30'
                      : 'text-enterprise-subtext hover:text-white hover:bg-gray-800/50'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Relationship type filter */}
            <div className="flex items-center gap-1.5 ml-auto">
              <Filter className="w-3.5 h-3.5 text-enterprise-subtext" />
              <select
                id="rel-type-filter"
                value={relFilter}
                onChange={e => setRelFilter(e.target.value)}
                className="bg-enterprise-card border border-enterprise-border rounded-lg text-xs text-gray-300 px-2 py-1.5 focus:outline-none focus:border-enterprise-accent"
              >
                {uniqueRelTypes.map(rt => (
                  <option key={rt} value={rt}>{rt === 'all' ? 'All Relationship Types' : rt}</option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Stats row */}
        {relData && (
          <div className="shrink-0 flex gap-4 px-6 py-3 border-b border-enterprise-border bg-enterprise-card/30">
            {[
              { label: 'Users', count: relData.entity_counts.users, icon: <User className="w-3.5 h-3.5 text-blue-400" /> },
              { label: 'Groups', count: relData.entity_counts.groups, icon: <Users className="w-3.5 h-3.5 text-purple-400" /> },
              { label: 'Roles', count: relData.entity_counts.roles, icon: <Shield className="w-3.5 h-3.5 text-amber-400" /> },
              { label: 'Policies', count: relData.entity_counts.policies, icon: <GitMerge className="w-3.5 h-3.5 text-green-400" /> },
              { label: 'Resources', count: relData.entity_counts.resources, icon: <Cloud className="w-3.5 h-3.5 text-cyan-400" /> },
            ].map(s => (
              <div key={s.label} className="flex items-center gap-1.5 text-xs text-enterprise-subtext">
                {s.icon} <span className="text-white font-semibold">{s.count}</span> {s.label}
              </div>
            ))}
          </div>
        )}

        {/* Relationship list */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-3">
          {showInitialLoading ? (
            <div className="flex items-center justify-center h-40 text-enterprise-subtext">
              <RefreshCw className="w-5 h-5 animate-spin mr-2" /> Loading relationships...
            </div>
          ) : isError && !hasExistingData ? (
            <div className="flex flex-col items-center justify-center h-48 gap-3 text-center p-6">
              <div className="w-10 h-10 rounded-full bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white">Unable to load relationships.</p>
                <p className="text-xs text-red-400/80 mt-1">{error instanceof Error ? error.message : 'An error occurred while fetching relationships'}</p>
              </div>
              <button
                onClick={() => refetch()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-enterprise-card hover:bg-gray-800 border border-enterprise-border text-xs text-white font-medium transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" /> Retry
              </button>
            </div>
          ) : grouped.length === 0 ? (
            isScanning && !hasCompletedSnapshot ? (
              <div className="flex flex-col items-center justify-center h-48 gap-3 text-center p-6">
                <RefreshCw className="w-8 h-8 text-enterprise-accent animate-spin" />
                <div>
                  <p className="text-sm font-semibold text-white">Initial CloudScope scan is running...</p>
                  <p className="text-xs text-enterprise-subtext mt-1">Discovering AWS IAM data and identity relationships. This will populate automatically.</p>
                </div>
              </div>
            ) : search || typeFilter !== 'all' || relFilter !== 'all' ? (
              <div className="flex flex-col items-center justify-center h-40 gap-2 text-enterprise-subtext">
                <Network className="w-8 h-8" />
                <p className="text-sm">No relationships match filter</p>
                <p className="text-xs">Try clearing search or filters</p>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-40 gap-2 text-enterprise-subtext">
                <Network className="w-8 h-8" />
                <p className="text-sm">No relationships found</p>
                <p className="text-xs">Run a scan to discover AWS IAM relationships</p>
              </div>
            )
          ) : (
            grouped.map(({ sourceId, sourceLabel, sourceType, rels }) => (
              <motion.div
                key={sourceId}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-enterprise-card border border-enterprise-border rounded-xl overflow-hidden"
              >
                {/* Source entity header */}
                <button
                  onClick={() => setSelectedEntity(selectedEntity === sourceId ? null : sourceId)}
                  className="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-800/30 transition-colors"
                >
                  <EntityIcon type={sourceType} />
                  <div className="flex-1 text-left">
                    <span className="text-sm font-semibold text-white">{sourceLabel}</span>
                    <span className="ml-2 text-[10px] text-enterprise-subtext font-mono">{sourceType}</span>
                  </div>
                  <span className="text-[10px] text-enterprise-subtext">
                    {rels.length} relationship{rels.length !== 1 ? 's' : ''}
                  </span>
                  <ChevronRight className={`w-4 h-4 text-enterprise-subtext transition-transform ${selectedEntity === sourceId ? 'rotate-90' : ''}`} />
                </button>

                {/* Relationships */}
                <div className="border-t border-enterprise-border divide-y divide-enterprise-border/50">
                  {rels.map((rel, i) => (
                    <div key={i} className="flex items-center gap-3 px-4 py-2.5 text-xs">
                      <span className="w-2 h-2 rounded-full bg-enterprise-border shrink-0 ml-2" />
                      <RelBadge rel={rel.relationship} />
                      <ArrowRight className="w-3 h-3 text-enterprise-subtext shrink-0" />
                      <div className="flex items-center gap-1.5 flex-1 min-w-0">
                        <EntityIcon type={rel.target_type} />
                        <span className="text-gray-300 truncate">{rel.target_label}</span>
                        <span className="text-[10px] text-enterprise-subtext font-mono shrink-0">({rel.target_type})</span>
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            ))
          )}
        </div>
      </div>

      {/* Right: Entity detail panel */}
      <AnimatePresence>
        {selectedEntity && entityData && (
          <motion.div
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 360, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="shrink-0 w-[360px] flex flex-col overflow-hidden bg-enterprise-card border-l border-enterprise-border"
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-enterprise-border">
              <div>
                <p className="text-sm font-semibold text-white">{entityData.entity_name}</p>
                <p className="text-[10px] text-enterprise-subtext">{entityData.entity_type}</p>
              </div>
              <button onClick={() => setSelectedEntity(null)} className="p-1 rounded hover:bg-gray-700 text-enterprise-subtext hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
              {/* Stats */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-enterprise-bg rounded-lg p-3 text-center">
                  <p className="text-xl font-bold text-white">{entityData.outgoing_count}</p>
                  <p className="text-[10px] text-enterprise-subtext">Outgoing</p>
                </div>
                <div className="bg-enterprise-bg rounded-lg p-3 text-center">
                  <p className="text-xl font-bold text-white">{entityData.incoming_count}</p>
                  <p className="text-[10px] text-enterprise-subtext">Incoming</p>
                </div>
              </div>

              {/* Relationships list */}
              <div>
                <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">All Relationships</p>
                <div className="space-y-1.5">
                  {entityData.relationships.map((r, i) => (
                    <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-enterprise-bg text-xs">
                      <EntityIcon type={r.source_type} />
                      <span className="text-gray-400 text-[10px] truncate max-w-[60px]">{r.source_label}</span>
                      <RelBadge rel={r.relationship} />
                      <ArrowRight className="w-3 h-3 text-enterprise-subtext shrink-0" />
                      <EntityIcon type={r.target_type} />
                      <span className="text-gray-300 text-[10px] truncate">{r.target_label}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Provenance chains */}
              {entityData.provenance && entityData.provenance.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Access Provenance</p>
                  <div className="space-y-2">
                    {entityData.provenance.slice(0, 10).map((p, i) => (
                      <div key={i} className="p-2 rounded-lg bg-enterprise-bg border border-enterprise-border">
                        <div className="flex flex-wrap items-center gap-1">
                          {p.chain.map((node, ni) => (
                            <span key={ni} className="flex items-center gap-1">
                              <span className="text-[10px] text-gray-300 font-mono">{node}</span>
                              {ni < p.chain.length - 1 && (
                                <span className="text-[10px] text-enterprise-subtext flex items-center gap-0.5">
                                  <ArrowRight className="w-2.5 h-2.5" />
                                  {p.relationships[ni] && (
                                    <span className="text-enterprise-accent text-[9px]">{p.relationships[ni]}</span>
                                  )}
                                </span>
                              )}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                    {entityData.provenance.length > 10 && (
                      <p className="text-[10px] text-enterprise-subtext text-center">
                        +{entityData.provenance.length - 10} more chains
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
