import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { AlertCircle, Clock, ShieldAlert, X, Copy, Check, Key } from 'lucide-react';

export const SecurityNoticeBanner: React.FC = () => {
  const { activeNotice, clearNotice } = useAuth();
  const [secondsRemaining, setSecondsRemaining] = useState<number>(0);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    if (activeNotice?.type === 'RATE_LIMIT' && activeNotice.retryAfter) {
      setSecondsRemaining(activeNotice.retryAfter);
      const timer = setInterval(() => {
        setSecondsRemaining((prev) => {
          if (prev <= 1) {
            clearInterval(timer);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
      return () => clearInterval(timer);
    }
  }, [activeNotice]);

  if (!activeNotice) return null;

  const copyRequestId = () => {
    if (activeNotice.requestId) {
      navigator.clipboard.writeText(activeNotice.requestId);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (activeNotice.type === 'RATE_LIMIT') {
    return (
      <div className="bg-amber-950/80 border-b border-amber-600/50 px-4 py-2.5 text-amber-200 flex items-center justify-between z-50 text-xs shadow-md">
        <div className="flex items-center gap-2.5 min-w-0">
          <Clock className="w-4 h-4 text-amber-400 shrink-0 animate-pulse" />
          <span className="font-semibold text-amber-300">Rate Limit Reached:</span>
          <span className="truncate">{activeNotice.message}</span>
          {secondsRemaining > 0 && (
            <span className="bg-amber-900/80 border border-amber-600/40 px-2 py-0.5 rounded text-amber-200 font-mono font-bold shrink-0">
              Retry in {secondsRemaining}s
            </span>
          )}
        </div>
        <button
          onClick={clearNotice}
          className="p-1 hover:bg-amber-900/50 rounded text-amber-300 hover:text-white transition-colors ml-4 shrink-0"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    );
  }

  if (activeNotice.type === 'FORBIDDEN') {
    return (
      <div className="bg-rose-950/80 border-b border-rose-600/50 px-4 py-2.5 text-rose-200 flex items-center justify-between z-50 text-xs shadow-md">
        <div className="flex items-center gap-2.5 min-w-0">
          <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
          <span className="font-semibold text-rose-300">Access Denied (403):</span>
          <span className="truncate">{activeNotice.message}</span>
        </div>
        <button
          onClick={clearNotice}
          className="p-1 hover:bg-rose-900/50 rounded text-rose-300 hover:text-white transition-colors ml-4 shrink-0"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    );
  }

  if (activeNotice.type === 'AUTH_ERROR') {
    return (
      <div className="bg-amber-950/90 border-b border-amber-600/60 px-4 py-2.5 text-amber-200 flex items-center justify-between z-50 text-xs shadow-md">
        <div className="flex items-center gap-2.5 min-w-0 flex-wrap">
          <Key className="w-4 h-4 text-amber-400 shrink-0" />
          <span className="font-semibold text-amber-300">Authentication Required (401):</span>
          <span className="truncate">{activeNotice.message}</span>
          {activeNotice.requestId && (
            <div className="flex items-center gap-1.5 bg-amber-900/60 border border-amber-700/50 px-2 py-0.5 rounded font-mono text-[11px] text-amber-100">
              <span>Request ID: {activeNotice.requestId}</span>
              <button
                onClick={copyRequestId}
                title="Copy Request ID for debugging"
                className="hover:text-white text-amber-300 ml-1"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          )}
        </div>
        <button
          onClick={clearNotice}
          className="p-1 hover:bg-amber-900/50 rounded text-amber-300 hover:text-white transition-colors ml-4 shrink-0"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    );
  }

  // SERVER_ERROR (HTTP 500+)
  return (
    <div className="bg-red-950/90 border-b border-red-600/60 px-4 py-2.5 text-red-200 flex items-center justify-between z-50 text-xs shadow-md">
      <div className="flex items-center gap-2.5 min-w-0 flex-wrap">
        <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
        <span className="font-semibold text-red-300">System Error:</span>
        <span className="truncate">{activeNotice.message}</span>
        {activeNotice.requestId && (
          <div className="flex items-center gap-1.5 bg-red-900/60 border border-red-700/50 px-2 py-0.5 rounded font-mono text-[11px] text-red-100">
            <span>Request ID: {activeNotice.requestId}</span>
            <button
              onClick={copyRequestId}
              title="Copy Request ID for debugging"
              className="hover:text-white text-red-300 ml-1"
            >
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>
        )}
      </div>
      <button
        onClick={clearNotice}
        className="p-1 hover:bg-red-900/50 rounded text-red-300 hover:text-white transition-colors ml-4 shrink-0"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
};
