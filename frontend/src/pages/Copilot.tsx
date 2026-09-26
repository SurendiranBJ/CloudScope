import { useState, useRef, useEffect } from 'react';
import { Bot, User, Send, Sparkles, Terminal, Trash2, AlertTriangle, ShieldAlert, CheckCircle2, HelpCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { postCopilotMessage, type CopilotMessage } from '../api/copilot';

export const Copilot: React.FC = () => {
  const [messages, setMessages] = useState<CopilotMessage[]>([
    {
      sender: 'ai',
      text: 'Hello Cloud Administrator. I am CloudScope Security Copilot powered by Gemini. I analyze direct and transitive IAM permissions, explain lateral attack paths, correlate CloudTrail events, and recommend evidence-grounded least-privilege remediations. Select a preset query or ask any security question.',
      summary: 'CloudScope Security Copilot Ready',
      suggestions: [
        'What are the highest-risk findings?',
        'Explain the most critical attack paths.',
        'Which identities have access to sensitive resources?',
        'What are the recommended IAM remediations?'
      ]
    }
  ]);
  const [inputVal, setInputVal] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  const presets = [
    { title: 'Highest-Risk Findings', query: 'What are the highest-risk findings detected in the environment?' },
    { title: 'Dangerous Attack Paths', query: 'Explain the most critical lateral movement and privilege escalation attack paths.' },
    { title: 'Sensitive Resource Exposure', query: 'Which identities have direct or transitive access to sensitive cloud resources?' },
    { title: 'IAM Least-Privilege Remediation', query: 'What are the recommended IAM policy remediations to reduce attack exposure?' },
    { title: 'Correlated CloudTrail Activity', query: 'What runtime CloudTrail activity correlates with our active attack paths?' }
  ];

  const handleSend = async (text: string) => {
    if (!text.trim()) return;

    // Add user message
    const userMsg: CopilotMessage = { sender: 'user', text };
    setMessages((prev) => [...prev, userMsg]);
    setInputVal('');
    setIsTyping(true);

    try {
      const response = await postCopilotMessage(text);
      setMessages((prev) => [...prev, response]);
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || 'Failed to communicate with AI Copilot service.';
      const cleanError = typeof detail === 'string' ? detail : 'An error occurred while generating the security analysis.';

      const errMessage: CopilotMessage = {
        sender: 'ai',
        text: `Unable to complete request: ${cleanError}`,
        summary: 'Analysis Unavailable',
        limitations: [cleanError],
        suggestions: ['Run a security scan first.', 'Check backend AI service configuration.']
      };
      setMessages((prev) => [...prev, errMessage]);
    } finally {
      setIsTyping(false);
    }
  };

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const clearChat = () => {
    setMessages([
      {
        sender: 'ai',
        text: 'Chat history cleared. Select a preset query below or ask any security question.',
        summary: 'Chat Cleared'
      }
    ]);
  };

  const getSeverityBadge = (severity?: string) => {
    if (!severity) return null;
    const sev = severity.toUpperCase();
    let colorClass = 'bg-gray-800 text-gray-300 border-gray-700';
    if (sev === 'CRITICAL') colorClass = 'bg-red-500/15 text-red-400 border-red-500/30';
    else if (sev === 'HIGH') colorClass = 'bg-orange-500/15 text-orange-400 border-orange-500/30';
    else if (sev === 'MEDIUM') colorClass = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    else if (sev === 'LOW') colorClass = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';

    return (
      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${colorClass}`}>
        {sev}
      </span>
    );
  };

  return (
    <div className="flex-1 p-6 flex flex-col lg:flex-row gap-6 overflow-hidden bg-enterprise-bg select-none">
      {/* Left panel - Preset Quick Actions */}
      <div className="w-full lg:w-72 bg-enterprise-card border border-enterprise-border p-5 rounded-xl flex flex-col gap-4 shrink-0 justify-between">
        <div className="space-y-4">
          <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
            <Sparkles className="w-4 h-4 text-enterprise-accent" />
            <span>Copilot Quick Actions</span>
          </h2>
          <p className="text-[10px] text-enterprise-subtext leading-relaxed">
            Click any action below to query Gemini with real CloudScope scan evidence and graph relationships.
          </p>
          <div className="space-y-2">
            {presets.map((p) => (
              <button
                key={p.title}
                onClick={() => handleSend(p.query)}
                disabled={isTyping}
                className="w-full text-left px-3 py-2 bg-enterprise-bg/60 border border-enterprise-border hover:border-gray-700 rounded-lg text-xs text-gray-200 hover:text-white transition-all hover:bg-gray-800/40 disabled:opacity-50"
              >
                {p.title}
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={clearChat}
          className="w-full py-2 bg-gray-900 border border-enterprise-border hover:bg-red-950/20 text-enterprise-subtext hover:text-enterprise-critical font-semibold rounded-lg text-xs transition-colors flex items-center justify-center gap-2"
        >
          <Trash2 className="w-4 h-4" />
          <span>Clear Chat Log</span>
        </button>
      </div>

      {/* Right panel - Chat Terminal Area */}
      <div className="flex-1 bg-enterprise-card border border-enterprise-border rounded-xl flex flex-col overflow-hidden min-h-[400px]">
        {/* Header */}
        <div className="p-4 border-b border-enterprise-border bg-enterprise-bg/25 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bot className="w-5 h-5 text-enterprise-accent" />
            <span className="font-bold text-sm text-white">AI Security Copilot</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-enterprise-accent/15 border border-enterprise-accent/30 text-enterprise-accent font-bold">
              Gemini 3.8 Flash • Evidence-Grounded
            </span>
          </div>
        </div>

        {/* Message Feed */}
        <div className="flex-1 p-5 overflow-y-auto space-y-4">
          {messages.map((msg, index) => (
            <div
              key={index}
              className={`flex gap-3 text-xs leading-relaxed max-w-[90%] ${
                msg.sender === 'user' ? 'ml-auto flex-row-reverse' : 'mr-auto'
              }`}
            >
              <div
                className={`w-7 h-7 rounded-lg flex items-center justify-center border shrink-0 ${
                  msg.sender === 'user'
                    ? 'bg-enterprise-accent/15 border-enterprise-accent/30 text-enterprise-accent'
                    : 'bg-gray-800 border-gray-700 text-enterprise-subtext'
                }`}
              >
                {msg.sender === 'user' ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              <div
                className={`p-4 rounded-xl border space-y-3 ${
                  msg.sender === 'user'
                    ? 'bg-enterprise-accent/5 border-enterprise-accent/10 text-white'
                    : 'bg-enterprise-bg/60 border-enterprise-border text-gray-200'
                }`}
              >
                {/* AI Structured Header (Summary, Severity, Risk Score) */}
                {msg.sender === 'ai' && (msg.summary || msg.severity || msg.riskScore !== undefined) && (
                  <div className="flex items-center justify-between flex-wrap gap-2 border-b border-gray-800/80 pb-2">
                    <div className="font-bold text-white text-xs flex items-center gap-2">
                      <ShieldAlert className="w-3.5 h-3.5 text-enterprise-accent" />
                      <span>{msg.summary || 'Security Assessment'}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {getSeverityBadge(msg.severity)}
                      {msg.riskScore !== undefined && msg.riskScore !== null && (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-gray-800 border border-gray-700 text-gray-300">
                          Risk Score: <strong className="text-white">{msg.riskScore}</strong>/100
                        </span>
                      )}
                    </div>
                  </div>
                )}

                {/* Primary Analysis Text */}
                <div className="whitespace-pre-wrap leading-relaxed">
                  {msg.analysis || msg.text}
                </div>

                {/* Affected Entities */}
                {msg.affectedEntities && msg.affectedEntities.length > 0 && (
                  <div className="space-y-1.5 pt-1">
                    <span className="text-[10px] font-bold text-enterprise-subtext uppercase tracking-wider block">
                      Affected Entities:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {msg.affectedEntities.map((ent, i) => (
                        <span key={i} className="px-2 py-0.5 bg-gray-800/80 border border-gray-700 rounded text-[10px] text-gray-300 font-mono">
                          {ent}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Evidence List */}
                {msg.evidence && msg.evidence.length > 0 && (
                  <div className="space-y-1.5 pt-1">
                    <span className="text-[10px] font-bold text-enterprise-subtext uppercase tracking-wider flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3 text-amber-400" />
                      <span>Authoritative Evidence:</span>
                    </span>
                    <ul className="space-y-1 pl-1">
                      {msg.evidence.map((ev, i) => (
                        <li key={i} className="text-[11px] text-gray-300 flex items-start gap-1.5">
                          <span className="text-enterprise-accent shrink-0">•</span>
                          <span>{ev}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Recommendations */}
                {msg.recommendations && msg.recommendations.length > 0 && (
                  <div className="space-y-1.5 pt-1">
                    <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                      <span>Remediation Guidance:</span>
                    </span>
                    <ul className="space-y-1 pl-1">
                      {msg.recommendations.map((rec, i) => (
                        <li key={i} className="text-[11px] text-gray-300 flex items-start gap-1.5">
                          <span className="text-emerald-400 shrink-0">✓</span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Code Block rendering */}
                {msg.codeBlock && (
                  <div className="space-y-1.5 pt-1">
                    <div className="flex items-center gap-1.5 text-[9px] text-enterprise-subtext font-bold uppercase">
                      <Terminal className="w-3.5 h-3.5 text-enterprise-accent" />
                      <span>Security Reference Payload</span>
                    </div>
                    <pre className="p-3 bg-gray-900 border border-enterprise-border rounded-lg text-[9px] font-mono text-gray-300 overflow-x-auto select-text leading-normal">
                      {msg.codeBlock}
                    </pre>
                  </div>
                )}

                {/* Limitations */}
                {msg.limitations && msg.limitations.length > 0 && (
                  <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-[10px] text-amber-300 space-y-1">
                    <span className="font-bold flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3 text-amber-400" />
                      <span>Scope Limitations:</span>
                    </span>
                    <ul className="list-disc pl-4 space-y-0.5 text-amber-200/90">
                      {msg.limitations.map((lim, i) => (
                        <li key={i}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Suggested Follow-up Questions */}
                {msg.suggestions && msg.suggestions.length > 0 && (
                  <div className="space-y-1.5 pt-2 border-t border-gray-800/80">
                    <span className="text-[9px] font-bold text-enterprise-subtext uppercase tracking-wider flex items-center gap-1">
                      <HelpCircle className="w-3 h-3 text-enterprise-accent" />
                      <span>Suggested Follow-Ups:</span>
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {msg.suggestions.map((sug, i) => (
                        <button
                          key={i}
                          onClick={() => handleSend(sug)}
                          disabled={isTyping}
                          className="px-2.5 py-1 bg-gray-800/80 hover:bg-gray-700/80 border border-gray-700 rounded-full text-[10px] text-gray-300 hover:text-white transition-colors text-left"
                        >
                          {sug}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}

          {/* Typing Indicator */}
          <AnimatePresence>
            {isTyping && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex gap-3 items-center text-xs text-enterprise-subtext"
              >
                <div className="w-7 h-7 rounded-lg bg-gray-800 border border-gray-700 flex items-center justify-center text-enterprise-subtext">
                  <Bot className="w-4 h-4" />
                </div>
                <div className="flex gap-1.5 px-3 py-2 bg-enterprise-bg/60 border border-enterprise-border rounded-lg">
                  <span className="w-1.5 h-1.5 bg-enterprise-accent rounded-full typing-dot" />
                  <span className="w-1.5 h-1.5 bg-enterprise-accent rounded-full typing-dot" />
                  <span className="w-1.5 h-1.5 bg-enterprise-accent rounded-full typing-dot" />
                </div>
              </motion.div>
            )}
          </AnimatePresence>
          <div ref={chatEndRef} />
        </div>

        {/* Input Bar */}
        <div className="p-4 border-t border-enterprise-border bg-enterprise-bg/25">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend(inputVal);
            }}
            className="flex gap-2"
          >
            <input
              type="text"
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              disabled={isTyping}
              placeholder="Ask the Security Copilot about attack vectors, group configurations, or least-privilege updates..."
              className="flex-1 bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-4 py-2.5 text-xs text-white placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent transition-colors disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={isTyping || !inputVal.trim()}
              className="px-4 py-2 bg-enterprise-accent hover:bg-blue-600 disabled:bg-gray-800 text-white font-semibold rounded-lg text-xs transition-colors flex items-center justify-center gap-1 glow-blue disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Ask AI</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
