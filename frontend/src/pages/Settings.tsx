import { useState } from 'react';
import { Settings, Shield, Bell, Key, RefreshCw, CheckCircle, Mail, MessageSquare } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [scanInterval, setScanInterval] = useState('10');
  const [slackEnabled, setSlackEnabled] = useState(true);
  const [emailEnabled, setEmailEnabled] = useState(true);
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
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
          Configure scanning intervals, notification webhooks, and administrative accounts.
        </p>
      </div>

      <form onSubmit={handleSave} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
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

          {/* Notifications Channels */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 border-b border-enterprise-border pb-3">
              <Bell className="w-4 h-4 text-enterprise-accent" />
              <span>Security Event Notifications</span>
            </h2>
            <div className="space-y-4">
              {/* Slack */}
              <div className="flex items-center justify-between p-3 bg-enterprise-bg/40 border border-enterprise-border rounded-lg">
                <div className="flex items-center gap-3">
                  <MessageSquare className="w-5 h-5 text-purple-400 shrink-0" />
                  <div className="text-xs">
                    <p className="font-bold text-white">Slack Webhook alerts</p>
                    <p className="text-[10px] text-enterprise-subtext">Post critical alerts to channel #security-findings</p>
                  </div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={slackEnabled}
                    onChange={() => setSlackEnabled(!slackEnabled)}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-gray-800 rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-enterprise-accent" />
                </label>
              </div>

              {/* Email */}
              <div className="flex items-center justify-between p-3 bg-enterprise-bg/40 border border-enterprise-border rounded-lg">
                <div className="flex items-center gap-3">
                  <Mail className="w-5 h-5 text-blue-400 shrink-0" />
                  <div className="text-xs">
                    <p className="font-bold text-white">Email Notification Digests</p>
                    <p className="text-[10px] text-enterprise-subtext">Send weekly security assessment rollups</p>
                  </div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={emailEnabled}
                    onChange={() => setEmailEnabled(!emailEnabled)}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-gray-800 rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-enterprise-accent" />
                </label>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column - User Profile & Action */}
        <div className="space-y-6">
          {/* User Profile */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 border-b border-enterprise-border pb-3">
              <Key className="w-4 h-4 text-enterprise-accent" />
              <span>User Profile & Sandbox Role</span>
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

          {/* Action Button */}
          <button
            type="submit"
            className="w-full py-2.5 bg-enterprise-accent hover:bg-blue-600 active:bg-blue-700 text-white font-bold rounded-lg text-xs transition-colors flex items-center justify-center gap-2 glow-blue"
          >
            {saved ? (
              <>
                <CheckCircle className="w-4 h-4" />
                <span>Configuration Saved</span>
              </>
            ) : (
              <span>Save System Settings</span>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
