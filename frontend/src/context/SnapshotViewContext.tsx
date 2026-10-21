import React, { createContext, useContext, useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

interface SnapshotViewValue {
  snapshotId: string | null;
  selectSnapshot: (snapshotId: string) => void;
  exitSnapshot: () => void;
}

const SnapshotViewContext = createContext<SnapshotViewValue | null>(null);
const STORAGE_KEY = 'cloudscope_snapshot_view';

export const SnapshotViewProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const queryClient = useQueryClient();
  const [snapshotId, setSnapshotId] = useState<string | null>(() => localStorage.getItem(STORAGE_KEY));
  const changeSnapshot = (next: string | null) => {
    if (next) localStorage.setItem(STORAGE_KEY, next);
    else localStorage.removeItem(STORAGE_KEY);
    queryClient.clear();
    setSnapshotId(next);
  };
  const value = useMemo(() => ({
    snapshotId,
    selectSnapshot: (id: string) => changeSnapshot(id),
    exitSnapshot: () => changeSnapshot(null),
  }), [snapshotId]);
  return <SnapshotViewContext.Provider value={value}>{children}</SnapshotViewContext.Provider>;
};

export const useSnapshotView = () => {
  const value = useContext(SnapshotViewContext);
  if (!value) throw new Error('useSnapshotView must be used within SnapshotViewProvider');
  return value;
};
