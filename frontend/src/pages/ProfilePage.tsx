import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { useInvestigationStore } from '../stores/investigationStore';
import { User, Mail, Building, Award, CheckCircle2, LogOut } from 'lucide-react';

export const ProfilePage: React.FC = () => {
  const { currentUser, updateProfile, logout } = useInvestigationStore();

  const [name, setName] = useState(currentUser?.name || '');
  const email = currentUser?.email || '';
  const [org, setOrg] = useState(currentUser?.organization || '');
  const [badge, setBadge] = useState(currentUser?.badge_id || '');
  const [savedMsg, setSavedMsg] = useState('');

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    updateProfile({
      name,
      email,
      organization: org,
      badge_id: badge
    });
    setSavedMsg('Investigator profile updated.');
    setTimeout(() => setSavedMsg(''), 3000);
  };

  return (
    <PageContainer
      title="Investigator Profile & Credentials"
      subtitle="Chain of custody provenance records every forensic action against this authenticated identity."
    >
      <div className="space-y-6 max-w-3xl">
        {savedMsg && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs rounded-lg flex items-center gap-2 font-mono">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{savedMsg}</span>
          </div>
        )}

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-bold font-mono text-lg">
                {currentUser?.name?.charAt(0) || 'U'}
              </div>
              <div>
                <h3 className="font-bold text-sm text-slate-100">{currentUser?.name || 'Investigator'}</h3>
                <p className="text-xs text-slate-400 font-mono">{currentUser?.role || 'INVESTIGATOR'} &bull; {currentUser?.organization || 'Digital Forensics Unit'}</p>
              </div>
            </div>

            <button
              onClick={() => logout()}
              className="px-3 py-1.5 bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 font-mono text-xs rounded-lg border border-rose-800/50 transition-colors flex items-center gap-1.5"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign Out</span>
            </button>
          </div>

          <form onSubmit={handleSave} className="space-y-4 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-400 mb-1 font-mono text-[11px]">Full Name</label>
                <div className="relative">
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500"
                  />
                  <User className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono text-[11px]">Workstation Email</label>
                <div className="relative">
                  <input
                    type="email"
                    required
                    readOnly
                    value={email}
                    className="w-full bg-slate-950/60 border border-slate-800/80 rounded-lg pl-8 pr-3 py-2 text-slate-400 cursor-not-allowed"
                  />
                  <Mail className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono text-[11px]">Organization / Agency</label>
                <div className="relative">
                  <input
                    type="text"
                    value={org}
                    onChange={(e) => setOrg(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500"
                  />
                  <Building className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono text-[11px]">Badge / Investigator ID</label>
                <div className="relative">
                  <input
                    type="text"
                    value={badge}
                    onChange={(e) => setBadge(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
                  />
                  <Award className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800/80">
              <button
                type="submit"
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-mono font-medium rounded-lg text-xs shadow-md shadow-indigo-500/20"
              >
                Save Profile
              </button>
            </div>
          </form>
        </div>
      </div>
    </PageContainer>
  );
};
