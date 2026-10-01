import React, { useState } from 'react';
import { useInvestigationStore } from '../stores/investigationStore';
import { ShieldCheck, Lock, Mail, User, X, ShieldAlert, Building2, BadgeCheck } from 'lucide-react';

export const AuthModal: React.FC = () => {
  const { isAuthModalOpen, setAuthModalOpen, login, signup, loading } = useInvestigationStore();
  const [tab, setTab] = useState<'login' | 'signup' | 'forgot'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [organization, setOrganization] = useState('Digital Forensics Unit');
  const [badgeId, setBadgeId] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  if (!isAuthModalOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');

    if (tab === 'login') {
      if (!email || !password) {
        setErrorMsg('Please enter your email and password.');
        return;
      }
      try {
        await login({ email, password });
        setSuccessMsg('Authenticated successfully.');
      } catch (err: any) {
        setErrorMsg(err.message || 'Invalid email or password.');
      }
    } else if (tab === 'signup') {
      if (!email || !password || !name) {
        setErrorMsg('Name, email, and password are required.');
        return;
      }
      if (password.length < 8) {
        setErrorMsg('Password must be at least 8 characters long.');
        return;
      }
      try {
        await signup({
          email,
          name,
          password,
          organization: organization || 'Digital Forensics Unit',
          badge_id: badgeId || undefined
        });
        setSuccessMsg('Account registered and authenticated.');
      } catch (err: any) {
        setErrorMsg(err.message || 'Failed to create investigator profile.');
      }
    }
  };

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 z-50 select-none font-sans">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl relative">
        <button
          onClick={() => setAuthModalOpen(false)}
          className="absolute right-4 top-4 text-slate-500 hover:text-slate-300"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-indigo-600 rounded-xl text-white shadow-md shadow-indigo-500/20">
            <ShieldAlert className="w-5 h-5 text-indigo-100" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 tracking-wide font-mono">ADFIR ACCESS CONTROL</h3>
            <p className="text-[11px] text-slate-400">Forensic Workstation Authentication</p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex border-b border-slate-800 text-xs font-medium">
          <button
            onClick={() => { setTab('login'); setErrorMsg(''); setSuccessMsg(''); }}
            className={`pb-2 px-3 transition-colors ${tab === 'login' ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Sign In
          </button>
          <button
            onClick={() => { setTab('signup'); setErrorMsg(''); setSuccessMsg(''); }}
            className={`pb-2 px-3 transition-colors ${tab === 'signup' ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Sign Up
          </button>
          <button
            onClick={() => { setTab('forgot'); setErrorMsg(''); setSuccessMsg(''); }}
            className={`pb-2 px-3 transition-colors ${tab === 'forgot' ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Forgot Password
          </button>
        </div>

        {successMsg && (
          <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs rounded-lg flex items-center gap-2 font-mono">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {errorMsg && (
          <div className="p-2.5 bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs rounded-lg flex items-center gap-2 font-mono">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {tab === 'forgot' ? (
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-xs space-y-3 text-slate-300">
            <p className="font-semibold text-slate-200">Workstation Password Recovery</p>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Self-service password reset is not currently available for local forensic workstation accounts.
              Please contact your Digital Forensics Unit system administrator to reset your credentials.
            </p>
            <div className="pt-2">
              <button
                type="button"
                onClick={() => setTab('login')}
                className="w-full py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-mono text-[11px] transition-colors"
              >
                Return to Sign In
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-3 text-xs">
            {tab === 'signup' && (
              <>
                <div>
                  <label className="block text-slate-400 mb-1 font-mono text-[11px]">Investigator Name</label>
                  <div className="relative">
                    <input
                      type="text"
                      required
                      placeholder="e.g. Detective John Miller"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500 font-sans"
                    />
                    <User className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-mono text-[11px]">Organization / Unit</label>
                  <div className="relative">
                    <input
                      type="text"
                      placeholder="Digital Forensics Unit"
                      value={organization}
                      onChange={(e) => setOrganization(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500 font-sans"
                    />
                    <Building2 className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-mono text-[11px]">Badge / ID (Optional)</label>
                  <div className="relative">
                    <input
                      type="text"
                      placeholder="DFIR-8821"
                      value={badgeId}
                      onChange={(e) => setBadgeId(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500 font-sans"
                    />
                    <BadgeCheck className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
              </>
            )}

            <div>
              <label className="block text-slate-400 mb-1 font-mono text-[11px]">Workstation Email</label>
              <div className="relative">
                <input
                  type="email"
                  required
                  placeholder="investigator@adfir.local"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500 font-sans"
                />
                <Mail className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              </div>
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-mono text-[11px]">Credentials Password</label>
              <div className="relative">
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500 font-sans"
                />
                <Lock className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              </div>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={loading}
                className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg font-mono font-medium shadow-md shadow-indigo-500/20 text-xs transition-colors flex items-center justify-center gap-2"
              >
                {loading && <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
                {tab === 'login' && (loading ? 'Authenticating...' : 'Sign In to Workstation')}
                {tab === 'signup' && (loading ? 'Initializing Profile...' : 'Create Forensic Profile')}
              </button>
            </div>
          </form>
        )}

        {/* Auth Method Badges */}
        <div className="pt-3 border-t border-slate-800/80 space-y-1.5 text-[11px] font-mono">
          <div className="flex items-center justify-between text-slate-400">
            <span>Local Workstation Auth:</span>
            <span className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20 text-[10px]">VERIFIED BACKEND</span>
          </div>
          <div className="flex items-center justify-between text-slate-500">
            <span>Enterprise Google SSO:</span>
            <span className="text-slate-500 bg-slate-800 px-1.5 py-0.5 rounded text-[10px]">NOT CONFIGURED</span>
          </div>
        </div>
      </div>
    </div>
  );
};
