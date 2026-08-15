import { useState } from 'react';
import { Settings, Shield, Bell, Key, RefreshCw, CheckCircle, AlertCircle } from 'lucide-react';
import { postScanInterval } from '../api/settings';

export const SettingsPage: React.FC = () => {
  const [scanInterval, setScanInterval] = useState('10');
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');
  const [errorMsg, setErrorMsg] = useState('');

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
          Configure scanning intervals and administrative accounts.
        </p>
      </div>

      <form onSubmit={handleSaveScanInterval} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - General Settings */}
        <div className="lg:col-span-2 space-y-6">
          {/* AWS Account Sync */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 border-b border-enterprise-border pb-3">
              <Shield className="w-4 h-4 text-enterprise-accent" />
              <span>AWS Account Sync Configuration</span>
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="space-y-1">
                <span className="text-enterprise-subtext">AWS Account ID:</span>
                <input
                  type="text"
                  value="123456789012"
                  disabled
                  className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-3 py-2 text-xs text-enterprise-subtext cursor-not-allowed focus:outline-none"
                />
              </div>
              <div className="space-y-1">
                <span className="text-enterprise-subtext">Sync Authorization Role ARN:</span>
                <input
                  type="text"
                  value="arn:aws:iam::123456789012:role/IdentityScopeReaderRole"
                  disabled
                  className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-3 py-2 text-xs text-enterprise-subtext cursor-not-allowed focus:outline-none"
                />
              </div>
            </div>
          </div>

          {/* Scanning Frequencies */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 border-b border-enterprise-border pb-3">
              <RefreshCw className="w-4 h-4 text-enterprise-accent animate-spin-slow" />
              <span>Configuration Scanning Intervals</span>
            </h2>
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
              <div className="flex gap-4">
                {[
                  { value: '10', label: '10 Minutes (High Frequency)' },
                  { value: '30', label: '30 Minutes' },
                  { value: '60', label: '1 Hour (Recommended)' }
                ].map((opt) => (
                  <label
                    key={opt.value}
                    className={`flex-1 p-3 rounded-lg border text-center cursor-pointer transition-all duration-150 ${
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

          {/* Notification Integrations — Coming Soon */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl space-y-4 opacity-60">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 border-b border-enterprise-border pb-3">
              <Bell className="w-4 h-4 text-enterprise-accent" />
              <span>Security Event Notifications</span>
              <span className="ml-auto text-[9px] font-bold px-2 py-0.5 rounded bg-gray-700 text-gray-400 uppercase tracking-wider">
                Coming Soon
              </span>
            </h2>
            <p className="text-xs text-enterprise-subtext leading-relaxed">
              Slack webhook alerts and email notification digests are planned for a future release.
              Notification integrations will be configurable here once the backend integration is complete.
            </p>
          </div>
        </div>

        {/* Right Column - User Profile & Action */}
        <div className="space-y-6">
          {/* User Profile */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 border-b border-enterprise-border pb-3">
              <Key className="w-4 h-4 text-enterprise-accent" />
              <span>User Profile &amp; Sandbox Role</span>
            </h2>
            <div className="space-y-3 text-xs">
              <div className="space-y-1">
                <span className="text-enterprise-subtext">Account Identity:</span>
                <p className="font-bold text-white">Cloud Admin (admin@identityscope.io)</p>
              </div>
              <div className="space-y-1">
                <span className="text-enterprise-subtext">Assigned Role Scope:</span>
                <p className="font-bold text-enterprise-success">PlatformAdministrator</p>
              </div>
              <div className="space-y-1">
                <span className="text-enterprise-subtext">Authorized capabilities:</span>
                <ul className="list-disc list-inside text-[10px] text-enterprise-subtext space-y-1 mt-1 pl-1">
                  <li>Configure sync scopes</li>
                  <li>Modify alert notifications</li>
                  <li>Trigger simulation tests</li>
                  <li>Read all policy documents</li>
                </ul>
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
