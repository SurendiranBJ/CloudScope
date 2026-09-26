import React from 'react';
import { ShieldCheck, AlertCircle, CheckCircle2 } from 'lucide-react';
import { useScanLifecycle } from '../hooks/useScanLifecycle';

export const ScanTrigger: React.FC = () => {
  const {
    isScanning,
    scanJustCompleted,
    scanError,
    elapsedFormatted,
    lastSuccessfulScanAt,
    isPartial,
    triggerScan,
    manualTriggerNotice,
  } = useScanLifecycle();

  return (
    <div className="relative inline-flex items-center">
      <button
        disabled={isScanning}
        onClick={triggerScan}
        title={
          scanError
            ? `Error: ${scanError}`
            : lastSuccessfulScanAt
              ? `Last successful scan: ${new Date(lastSuccessfulScanAt).toLocaleTimeString()}`
              : 'Trigger a fresh AWS security scan'
        }
        className={`relative flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all select-none ${
          scanError
            ? 'bg-enterprise-critical/20 text-enterprise-critical border border-enterprise-critical/30 hover:bg-enterprise-critical/30'
            : scanJustCompleted
              ? 'bg-enterprise-success/20 text-enterprise-success border border-enterprise-success/30'
              : isScanning
                ? 'bg-blue-600/15 text-blue-300 border border-blue-500/30 cursor-wait'
                : 'bg-blue-600/20 hover:bg-blue-600/35 text-blue-400 border border-blue-500/30 shadow-sm active:scale-95'
        }`}
      >
        {scanError ? (
          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
        ) : scanJustCompleted ? (
          <CheckCircle2 className="w-3.5 h-3.5 shrink-0 text-enterprise-success" />
        ) : isScanning ? (
          <svg
            className="animate-spin w-3.5 h-3.5 shrink-0 text-blue-400"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        ) : (
          <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
        )}

        <span>
          {scanError
            ? 'Scan Failed'
            : manualTriggerNotice
              ? manualTriggerNotice
              : scanJustCompleted
                ? isPartial
                  ? 'Scan Partial'
                  : 'Scan Complete'
                : isScanning
                  ? `Scanning ${elapsedFormatted}`
                  : 'Scan AWS'}
        </span>
      </button>
    </div>
  );
};

export const useScanTrigger = () => {
  const { triggerScan } = useScanLifecycle();
  return { handleScanClick: triggerScan };
};

