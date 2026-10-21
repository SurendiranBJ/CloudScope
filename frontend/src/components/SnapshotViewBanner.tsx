import { useQuery } from '@tanstack/react-query';
import { Clock3, LogOut, ShieldAlert } from 'lucide-react';
import { getSnapshotHistory } from '../api/snapshots';
import { useSnapshotView } from '../context/SnapshotViewContext';

export const SnapshotViewBanner: React.FC = () => {
  const { snapshotId, exitSnapshot } = useSnapshotView();
  const { data = [] } = useQuery({ queryKey: ['snapshot-history'], queryFn: getSnapshotHistory, enabled: !!snapshotId, staleTime: 60_000 });
  if (!snapshotId) return null;
  const selected = data.find((snapshot) => snapshot.snapshot_id === snapshotId);
  const counts = selected?.resource_counts || {};
  const resourceTotal = Object.values(counts).reduce((sum, value) => sum + (Number(value) || 0), 0);
  const findingCounts = selected?.finding_counts || {};
  const findingTotal = Object.values(findingCounts).reduce((sum, value) => sum + (Number(value) || 0), 0);
  const regionCount = Object.keys(selected?.regions || {}).length;
  return <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-amber-400/30 bg-amber-400/10 px-5 py-2.5 text-xs text-amber-100">
    <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1"><Clock3 className="h-4 w-4 shrink-0 text-amber-300" /><strong className="text-amber-200">Historical snapshot view</strong><span>All scan data below is from</span><code className="rounded bg-black/20 px-1.5 py-0.5 font-mono font-bold">{snapshotId}</code>{selected && <><span>· {new Date(selected.published_at).toLocaleString()}</span><span>· {selected.status}</span><span>· {regionCount} regions</span><span>· {resourceTotal} resources</span><span>· {findingTotal} findings</span></>}{!selected && <span>Loading snapshot details…</span>}</div>
    <div className="flex items-center gap-3"><span className="hidden items-center gap-1 text-amber-200/80 sm:inline-flex"><ShieldAlert className="h-3.5 w-3.5" /> Read-only view</span><button type="button" onClick={exitSnapshot} className="inline-flex items-center gap-1.5 rounded-md border border-amber-300/40 bg-amber-200/10 px-2.5 py-1.5 font-semibold text-white hover:bg-amber-200/20"><LogOut className="h-3.5 w-3.5" />Exit to live data</button></div>
  </div>;
};
