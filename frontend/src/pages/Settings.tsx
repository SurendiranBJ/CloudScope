import { useState, useEffect } from 'react';
import { Settings, RefreshCw, CheckCircle, AlertCircle, Clock } from 'lucide-react';
import { postScanInterval } from '../api/settings';
import { useScanDataRefresh } from '../hooks/useScanDataRefresh';

export const SettingsPage: React.FC = () => {
  const { scheduledInterval, nextScheduledScanAt } = useScanDataRefresh();
  const [scanInterval, setScanInterval] = useState(String(scheduledInterval || 5));
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');
  const [errorMsg, setErrorMsg] = useState('');

  useEffect(() => {
    if (scheduledInterval) {
      setScanInterval(String(scheduledInterval));
    }
  }, [scheduledInterval]);

  const handleSaveScanInterval = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveState('saving');
    setErrorMsg('');
    try {
      await postScanInterval(Number(scanInterval));
      setSaveState('success');
      setTimeout(() => setSaveState('idle'), 4000);
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || 'Unknown error';
      setErrorMsg(detail);
      setSaveState('error');
      setTimeout(() => setSaveState('idle'), 5000);
    }
  };

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <Settings className="w-6 h-6 text-enterprise-subtext" />
          <span>Platform Settings</span>
        </h1>
        <p className="text-xs text-enterprise-subtext mt-1">
          Configure the automatic security scan schedule.
        </p>
      </div>

      <form onSubmit={handleSaveScanInterval} className="max-w-4xl">
        <div className="space-y-6">
          {/* Scanning Frequencies */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 border-b border-enterprise-border pb-3">
              <RefreshCw className="w-4 h-4 text-enterprise-accent animate-spin-slow" />
              <span>Configuration Scanning Intervals</span>
            </h2>

            {/* Live Scheduler Visibility (Requirement 26) */}
            <div className="bg-enterprise-bg/60 border border-enterprise-border/80 rounded-lg p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-enterprise-accent" />
                <div>
                  <span className="text-enterprise-subtext block text-[10px] uppercase font-semibold">Automatic scan:</span>
                  <span className="font-semibold text-white">Every {scheduledInterval} minutes</span>
                </div>
              </div>
              <div className="text-right">
                <span className="text-enterprise-subtext block text-[10px] uppercase font-semibold">Next scheduled scan:</span>
                <span className="font-mono text-enterprise-accent font-medium">
                  {nextScheduledScanAt ? new Date(nextScheduledScanAt).toLocaleTimeString() : 'Pending'}
                </span>
              </div>
            </div>

            <div className="space-y-3">
              <span className="text-xs text-enterprise-subtext block">
                Determine how often the platform polls AWS config logs and credential reports.
                Changes take effect immediately — update{' '}
                <code className="text-enterprise-accent font-mono text-[10px] bg-gray-900 px-1 py-0.5 rounded">
                  SCAN_INTERVAL_MINUTES
                </code>{' '}
                in <code className="text-enterprise-accent font-mono text-[10px] bg-gray-900 px-1 py-0.5 rounded">.env</code>{' '}
                to persist across server restarts.
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { value: '5', label: '5 Minutes (Default)' },
                  { value: '10', label: '10 Minutes' },
                  { value: '30', label: '30 Minutes' },
                  { value: '60', label: '1 Hour' }
                ].map((opt) => (
                  <label
                    key={opt.value}
                    className={`p-3 rounded-lg border text-center cursor-pointer transition-all duration-150 ${
                      scanInterval === opt.value
                        ? 'border-enterprise-accent bg-enterprise-accent/10 text-white font-bold'
                        : 'border-enterprise-border bg-enterprise-bg/40 text-enterprise-subtext hover:border-gray-700'
                    }`}
                  >
                    <input
                      type="radio"
                      name="scan_interval"
                      value={opt.value}
                      checked={scanInterval === opt.value}
                      onChange={() => setScanInterval(opt.value)}
                      className="hidden"
                    />
                    <span className="text-xs block">{opt.label}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>

          {/* Error feedback */}
          {saveState === 'error' && (
            <div className="flex items-start gap-2 p-3 bg-enterprise-critical/10 border border-enterprise-critical/30 rounded-lg text-xs text-enterprise-critical">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{errorMsg || 'Failed to update scan interval. Is the backend running?'}</span>
            </div>
          )}

          {/* Save Button */}
          <button
            type="submit"
            disabled={saveState === 'saving'}
            className="w-full py-2.5 bg-enterprise-accent hover:bg-blue-600 active:bg-blue-700 disabled:opacity-60 disabled:cursor-not-allowed text-white font-bold rounded-lg text-xs transition-colors flex items-center justify-center gap-2 glow-blue"
          >
            {saveState === 'saving' ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Applying...</span>
              </>
            ) : saveState === 'success' ? (
              <>
                <CheckCircle className="w-4 h-4" />
                <span>Interval Updated — every {scanInterval} min</span>
              </>
            ) : (
              <span>Save Scan Interval</span>
            )}
          </button>

          <p className="text-[10px] text-enterprise-subtext text-center leading-relaxed">
            Runtime change only. To persist across restarts, set{' '}
            <code className="font-mono text-enterprise-accent">SCAN_INTERVAL_MINUTES={scanInterval}</code>{' '}
            in your <code className="font-mono text-enterprise-accent">.env</code> file.
          </p>
        </div>
      </form>
    </div>
  );
};
