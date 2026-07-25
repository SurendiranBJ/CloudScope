import { useState, useRef, useEffect } from 'react';
import { Bot, User, Send, Sparkles, Terminal, Trash2 } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { postCopilotMessage } from '../api/copilot';

interface Message {
  sender: 'user' | 'ai';
  text: string;
  type?: 'text' | 'remediation' | 'analysis';
  codeBlock?: string;
}

export const Copilot: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: 'ai',
      text: 'Hello Cloud Administrator. I am your IdentityScope Security Copilot. I can analyze direct/transitive permissions, describe lateral attack paths, or suggest least-privilege IAM policy remediations. Select a preset query below or ask any security question.',
    }
  ]);
  const [inputVal, setInputVal] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  const presets = [
    { title: 'Explain Attack Path 1', query: 'Analyze the active Developer Path to PII S3 Bucket and explain the risk.' },
    { title: 'Find Over-Privileged Users', query: 'List all IAM users with excessive privileges or inactive console profiles.' },
    { title: 'Show Public Buckets', query: 'Scan S3 bucket assets and identify configurations exposing object resources to the public.' },
    { title: 'Recommend IAM Fixes', query: 'Suggest an updated least-privilege trust policy for the AWSAdminRole.' },
    { title: 'Generate Security Report', query: 'Provide a compliance summary checklist matching CIS AWS Foundations standards.' }
  ];

  const handleSend = async (text: string) => {
    if (!text.trim()) return;

    // Add user message
    const userMsg: Message = { sender: 'user', text };
    setMessages((prev) => [...prev, userMsg]);
    setInputVal('');
    setIsTyping(true);

    try {
      const response = await postCopilotMessage(text);
      setMessages((prev) => [...prev, {
        sender: response.sender as 'user' | 'ai',
        text: response.text,
        type: response.type,
        codeBlock: response.codeBlock
      }]);
    } catch (err) {
      // Graceful fallback to static logic
      let aiMsg: Message = {
        sender: 'ai',
        text: 'I apologize, I could not connect to the backend server. Using local backup: ...'
      };

      if (text.includes('Developer Path') || text.includes('Attack Path 1')) {
        aiMsg = {
          sender: 'ai',
          text: 'Security Analysis: The Developer Path represents a high-criticality attack vector. A local workstation compromise on developer-session allows credentials assumption of AWSAdminRole because the role lacks condition-based MFA restrictions. Once assumed, the attacker inherits full s3:* permissions, allowing them to access, download, or delete S3-Customer-PII-DB objects.',
          type: 'analysis',
          codeBlock: '# MITRE ATT&CK Mapping:\n- T1078 (Valid Accounts): Compromised local workstation credentials\n- T1548 (Abuse Elevation): sts:AssumeRole bypasses context\n- T1530 (Data from Cloud): Outbound leakage from customer S3 store'
        };
      } else if (text.includes('Over-Privileged')) {
        aiMsg = {
          sender: 'ai',
          text: 'Vulnerability Scan Summary: I found 2 highly over-privileged users:\n1. developer-session: Possesses wildcard inline S3 policies.\n2. ci-cd-runner: Houses permanent credentials keys that have not been rotated in 180+ days and can assume root AWSAdminRole.',
          type: 'analysis'
        };
      } else if (text.includes('Public Buckets')) {
        aiMsg = {
          sender: 'ai',
          text: 'Assets Scan Findings: S3-Public-Assets has public read settings enabled (BlockPublicAccess is FALSE). The S3-Customer-PII-DB bucket has custom policy rules that permit s3:GetObject globally without credential tokens. Immediate block recommended.',
          type: 'remediation',
          codeBlock: '# Block public buckets policy payload:\naws s3api put-public-access-block \\\n  --bucket s3-customer-pii-db-production \\\n  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"'
        };
      } else if (text.includes('trust policy') || text.includes('Recommend IAM Fixes')) {
        aiMsg = {
          sender: 'ai',
          text: 'Remediation Policy Suggested: Restrict the trust configuration document of AWSAdminRole to validate multi-factor authentication (MFA) and restrict access to internal corporate subnets:',
          type: 'remediation',
          codeBlock: '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": { "AWS": "arn:aws:iam::123456789012:user/developer-session" },\n      "Action": "sts:AssumeRole",\n      "Condition": {\n        "Bool": { "aws:MultiFactorAuthPresent": "true" },\n        "IpAddress": { "aws:SourceIp": "10.0.0.0/8" }\n      }\n    }\n  ]\n}'
        };
      } else if (text.includes('compliance summary') || text.includes('Security Report')) {
        aiMsg = {
          sender: 'ai',
          text: 'Compliance Posture Status Report (CIS v1.4.0):\n- Section 1.2: Enforce MFA for Console Access -> FAIL (developer-session/ci-cd-runner failed)\n- Section 1.12: Deactivate credentials key after 90 days -> FAIL (ci-cd-runner failed)\n- Section 2.1: Enforce encryption on all S3 Buckets -> PASS\n- Section 2.4: Enable CloudTrail logs in all regions -> PASS',
          type: 'analysis'
        };
      }
      setMessages((prev) => [...prev, aiMsg]);
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
      }
    ]);
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
            Click any action below to trigger a pre-configured threat analysis simulation or remediation prompt.
          </p>
          <div className="space-y-2">
            {presets.map((p) => (
              <button
                key={p.title}
                onClick={() => handleSend(p.query)}
                className="w-full text-left px-3 py-2 bg-enterprise-bg/60 border border-enterprise-border hover:border-gray-700 rounded-lg text-xs text-gray-200 hover:text-white transition-all hover:bg-gray-800/40"
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
            <span className="font-bold text-sm text-white">AI Copilot Terminal</span>
          </div>
          <span className="text-[10px] px-2 py-0.5 rounded bg-enterprise-accent/15 text-enterprise-accent font-bold">
            GPT-4o Security Engine
          </span>
        </div>

        {/* Message Feed */}
        <div className="flex-1 p-5 overflow-y-auto space-y-4">
          {messages.map((msg, index) => (
            <div
              key={index}
              className={`flex gap-3 text-xs leading-relaxed max-w-[85%] ${
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
                className={`p-3.5 rounded-xl border ${
                  msg.sender === 'user'
                    ? 'bg-enterprise-accent/5 border-enterprise-accent/10 text-white'
                    : 'bg-enterprise-bg/60 border-enterprise-border text-gray-200'
                }`}
              >
                <div className="whitespace-pre-wrap leading-relaxed">{msg.text}</div>
                {/* Code Block rendering */}
                {msg.codeBlock && (
                  <div className="space-y-1.5 mt-3">
                    <div className="flex items-center gap-1.5 text-[9px] text-enterprise-subtext font-bold uppercase">
                      <Terminal className="w-3.5 h-3.5 text-enterprise-accent" />
                      <span>Security Output Reference</span>
                    </div>
                    <pre className="p-3 bg-gray-900 border border-enterprise-border rounded-lg text-[9px] font-mono text-gray-300 overflow-x-auto select-text leading-normal">
                      {msg.codeBlock}
                    </pre>
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
              placeholder="Ask the Security Copilot about attack vectors, group configurations, or least-privilege updates..."
              className="flex-1 bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-4 py-2.5 text-xs text-white placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent transition-colors"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-enterprise-accent hover:bg-blue-600 text-white font-semibold rounded-lg text-xs transition-colors flex items-center justify-center gap-1 glow-blue"
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
