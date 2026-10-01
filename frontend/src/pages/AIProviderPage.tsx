import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { useInvestigationStore } from '../stores/investigationStore';
import {
  Key,
  ShieldAlert,
  CheckCircle2,
  AlertCircle,
  Lock,
  Loader2,
  Globe
} from 'lucide-react';

export const AIProviderPage: React.FC = () => {
  const {
    aiConfig,
    updateAIConfig,
    aiProviderTest,
    aiProviderTestLoading,
    aiProviderTestError,
    testAIProvider
  } = useInvestigationStore();

  const [provider, setProvider] = useState<'openai' | 'anthropic' | 'google' | 'local_stub'>(aiConfig.provider);
  const [model, setModel] = useState<string>(aiConfig.model);
  const [apiKey, setApiKey] = useState<string>('');
  const [baseUrl, setBaseUrl] = useState<string>('');
  const [saveStatusMsg, setSaveStatusMsg] = useState<string>('');

  const modelOptions = {
    openai: [
      { id: 'gpt-4o', label: 'GPT-4o (High Reasoning)' },
      { id: 'gpt-4o-mini', label: 'GPT-4o-mini (Fast)' },
      { id: 'o3-mini', label: 'o3-mini (Forensic Logic)' }
    ],
    anthropic: [
      { id: 'claude-3-5-sonnet', label: 'Claude 3.5 Sonnet (Forensic Analysis)' },
      { id: 'claude-3-5-haiku', label: 'Claude 3.5 Haiku (Fast)' },
      { id: 'claude-3-opus', label: 'Claude 3 Opus (Deep Analysis)' }
    ],
    google: [
      { id: 'gemini-1.5-pro', label: 'Gemini 1.5 Pro (Large Context)' },
      { id: 'gemini-1.5-flash', label: 'Gemini 1.5 Flash (Fast)' },
      { id: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash' }
    ],
    local_stub: [
      { id: 'adfir-deterministic-engine', label: 'Local Deterministic Template Engine (Default)' }
    ]
  };

  const handleTestConnection = async () => {
    if (aiProviderTestLoading) return;
    try {
      await testAIProvider({
        provider,
        model,
        api_key: apiKey.trim() || undefined,
        base_url: baseUrl.trim() || undefined
      });
    } catch {
      // Error captured in aiProviderTestError state
    } finally {
      // CRITICAL CREDENTIAL RULE: Clear transient API key input state after test submission
      setApiKey('');
    }
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    updateAIConfig({
      provider,
      model,
      has_key: Boolean(apiKey.trim() || provider === 'local_stub'),
      is_tested: aiProviderTest?.status === 'SUCCESS',
      status: (apiKey.trim() || provider === 'local_stub') ? 'CONFIGURED' : 'NOT_CONFIGURED',
      last_tested: new Date().toISOString()
    });
    // CRITICAL CREDENTIAL RULE: Clear transient API key input state after save
    setApiKey('');
    setSaveStatusMsg('AI Provider configuration saved securely.');
    setTimeout(() => setSaveStatusMsg(''), 4000);
  };

  return (
    <PageContainer
      title="AI Reasoning Provider Configuration"
      subtitle="Configure cloud or local LLM reasoning providers for forensic query analysis and finding explanations."
    >
      <div className="space-y-6 max-w-3xl">
        {/* Forensic Core Invariant Notice */}
        <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-2 font-mono text-xs">
          <div className="flex items-center gap-2 text-indigo-400 font-bold">
            <ShieldAlert className="w-4 h-4" />
            <span>CRITICAL FORENSIC INVARIANT & CREDENTIAL SECURITY</span>
          </div>
          <p className="text-slate-300 leading-relaxed font-sans text-xs">
            The LLM is <strong>NOT</strong> the source of forensic truth. Forensic tools (TSK, Volatility 3, YARA, python-evtx)
            extract facts and produce artifacts. The backend Verification Layer determines whether findings are supported.
            API keys submitted for testing exist <strong>transiently in-memory only</strong> and are never saved to disk, browser storage, or backend logs.
          </p>
        </div>

        {saveStatusMsg && (
          <div className="p-3 rounded-lg border text-xs font-mono flex items-center gap-2 bg-emerald-500/10 border-emerald-500/30 text-emerald-300">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{saveStatusMsg}</span>
          </div>
        )}

        {/* Backend Provider Test Error */}
        {aiProviderTestError && (
          <div className="p-3 rounded-lg border text-xs font-mono flex items-center gap-2 bg-rose-500/10 border-rose-500/30 text-rose-300">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>Provider Test Failed: {aiProviderTestError}</span>
          </div>
        )}

        {/* Backend Provider Test Response Display */}
        {aiProviderTest && (
          <div className={`p-4 rounded-xl border text-xs font-mono space-y-2 ${
            aiProviderTest.status === 'SUCCESS'
              ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-300'
              : 'bg-rose-950/30 border-rose-800/80 text-rose-300'
          }`}>
            <div className="flex items-center justify-between font-bold">
              <div className="flex items-center gap-2">
                {aiProviderTest.status === 'SUCCESS' ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-rose-400" />
                )}
                <span>Provider Test Result: [{aiProviderTest.status}]</span>
              </div>
              <span className="text-[10px] text-slate-400">Provider: {aiProviderTest.provider} ({aiProviderTest.model})</span>
            </div>
            <p className="text-[11px] text-slate-300 leading-relaxed font-sans">{aiProviderTest.details}</p>
          </div>
        )}

        {/* Configuration Form */}
        <form onSubmit={handleSave} className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-5 text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="font-mono text-slate-200 font-bold uppercase">Provider Credentials & Target</h3>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              aiConfig.status === 'CONFIGURED'
                ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                : 'text-amber-400 bg-amber-500/10 border-amber-500/20'
            }`}>
              {aiConfig.status}
            </span>
          </div>

          <div>
            <label className="block font-mono text-slate-400 mb-1.5 uppercase text-[11px]">Reasoning Provider</label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono">
              {[
                { id: 'local_stub', label: 'Local Engine' },
                { id: 'openai', label: 'OpenAI' },
                { id: 'anthropic', label: 'Anthropic' },
                { id: 'google', label: 'Google Gemini' }
              ].map((p) => (
                <button
                  type="button"
                  key={p.id}
                  onClick={() => {
                    setProvider(p.id as any);
                    setModel(modelOptions[p.id as keyof typeof modelOptions][0].id);
                  }}
                  className={`p-2.5 rounded-lg border text-center transition-all ${
                    provider === p.id
                      ? 'bg-indigo-600/20 border-indigo-500 text-indigo-300 font-bold'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block font-mono text-slate-400 mb-1.5 uppercase text-[11px]">Model Target</label>
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
            >
              {(modelOptions[provider as keyof typeof modelOptions] || []).map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>
          </div>

          {provider !== 'local_stub' && (
            <div className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="font-mono text-slate-400 uppercase text-[11px]">API Key (Runtime Only)</label>
                  <span className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                    <Lock className="w-3 h-3" /> Never stored in disk, localStorage or logs
                  </span>
                </div>
                <div className="relative">
                  <input
                    type="password"
                    placeholder="sk-••••••••••••••••••••••••••••••••"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
                  />
                  <Key className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="font-mono text-slate-400 uppercase text-[11px]">Custom Base URL (Optional)</label>
                  <span className="text-[10px] text-slate-500 font-mono">For local/compatible endpoints</span>
                </div>
                <div className="relative">
                  <input
                    type="text"
                    placeholder="https://api.openai.com/v1"
                    value={baseUrl}
                    onChange={(e) => setBaseUrl(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
                  />
                  <Globe className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                </div>
              </div>
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800/80 font-mono">
            <button
              type="button"
              onClick={handleTestConnection}
              disabled={aiProviderTestLoading}
              className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-300 rounded-lg text-xs transition-colors"
            >
              {aiProviderTestLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Testing Connection...</span>
                </>
              ) : (
                <span>Test Connection</span>
              )}
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded-lg text-xs shadow-md shadow-indigo-500/20 transition-colors"
            >
              Save Configuration
            </button>
          </div>
        </form>
      </div>
    </PageContainer>
  );
};
