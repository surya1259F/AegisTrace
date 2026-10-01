import React, { useState, useMemo } from 'react';
import {
  Search,
  LayoutDashboard,
  FolderKanban,
  HardDrive,
  Activity,
  Layers,
  Sparkles,
  ShieldCheck,
  FileText,
  Clock,
  Settings,
  User,
  LogOut,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  Command,
  X,
  Plus
} from 'lucide-react';
import { useInvestigationStore } from '../../stores/investigationStore';

export type NavItemData = {
  id: string;
  title: string;
  icon: React.ElementType;
  badge?: number | string;
  shortcut?: string;
  children?: NavItemData[];
};

export type NavGroupData = {
  heading?: string;
  items: NavItemData[];
};

function WorkspaceSwitcher() {
  const [isOpen, setIsOpen] = useState(false);
  const { activeInvestigation, investigations, setActiveInvestigation, setCurrentTab } = useInvestigationStore();

  const currentName = activeInvestigation?.name || "Select Investigation";
  const caseSubtext = activeInvestigation?.case_number || (activeInvestigation ? `ID: ${activeInvestigation.id.slice(0, 8)}` : "No Case Active");

  return (
    <div className="relative font-sans select-none">
      <div
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center justify-between px-3 py-2 mb-3 rounded-xl bg-slate-800/40 hover:bg-slate-800/80 border border-slate-800 cursor-pointer transition-colors group shadow-xs"
      >
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-indigo-600 text-white flex items-center justify-center font-bold text-xs shadow-md shadow-indigo-500/20 shrink-0">
            {currentName.charAt(0).toUpperCase()}
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-xs font-semibold text-slate-100 truncate max-w-[120px]">
              {currentName}
            </span>
            <span className="text-[10px] text-slate-400 font-mono leading-none mt-0.5 truncate">
              {caseSubtext}
            </span>
          </div>
        </div>
        <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-slate-200 transition-colors shrink-0" />
      </div>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
          <div className="absolute top-[52px] left-0 w-full bg-slate-900 border border-slate-800 rounded-xl shadow-2xl z-50 py-1.5 flex flex-col gap-1 font-sans">
            <span className="px-3 py-1 text-[10px] font-mono text-slate-400 uppercase font-semibold">Active Cases</span>
            {investigations.length > 0 ? (
              investigations.map((inv) => (
                <div
                  key={inv.id}
                  onClick={() => {
                    setActiveInvestigation(inv);
                    setIsOpen(false);
                  }}
                  className={`px-3 py-2 mx-1.5 text-xs rounded-lg cursor-pointer transition-colors ${
                    activeInvestigation?.id === inv.id
                      ? 'bg-indigo-600/20 text-indigo-400 font-semibold border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800/60'
                  }`}
                >
                  <div className="truncate font-semibold">{inv.name}</div>
                  <div className="text-[10px] text-slate-400 font-mono mt-0.5">{inv.case_number || inv.id.slice(0, 8)}</div>
                </div>
              ))
            ) : (
              <div className="px-3 py-1.5 text-xs text-slate-400 font-mono">No cases created yet</div>
            )}
            <div className="h-px bg-slate-800 my-1 mx-2" />
            <div
              onClick={() => {
                setIsOpen(false);
                setCurrentTab('cases');
              }}
              className="px-3 py-1.5 mx-1.5 text-xs text-indigo-400 hover:bg-indigo-950/40 rounded-lg cursor-pointer flex items-center gap-2 transition-colors font-mono font-semibold"
            >
              <Plus className="w-4 h-4" /> Initialize New Case
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function NavItem({
  item,
  activeId,
  onSelect,
  level = 0
}: {
  item: NavItemData;
  activeId: string;
  onSelect: (id: string) => void;
  level?: number;
}) {
  const isActive = activeId === item.id;
  const hasChildren = !!item.children;
  const [isOpen, setIsOpen] = useState(false);

  const handleClick = () => {
    if (hasChildren) {
      setIsOpen(!isOpen);
    } else {
      onSelect(item.id);
    }
  };

  const Icon = item.icon;

  return (
    <div className="flex flex-col w-full font-sans select-none">
      <div
        className={`group flex items-center justify-between px-3 py-2 rounded-xl cursor-pointer transition-all duration-200 text-xs font-medium ${
          isActive
            ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 font-semibold shadow-xs'
            : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-100'
        }`}
        style={{ paddingLeft: `${level * 12 + 12}px` }}
        onClick={handleClick}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-indigo-400' : 'text-slate-400 group-hover:text-slate-200'}`} />
          <span className="truncate">{item.title}</span>
        </div>

        <div className="flex items-center gap-2">
          {item.shortcut && (
            <kbd className="hidden group-hover:inline-flex items-center justify-center h-4 px-1.5 text-[9px] font-mono text-slate-400 bg-slate-950 border border-slate-800 rounded">
              {item.shortcut}
            </kbd>
          )}
          {item.badge && (
            <span className="flex items-center justify-center min-w-[18px] h-4.5 px-1.5 text-[9px] font-mono font-bold rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
              {item.badge}
            </span>
          )}
          {hasChildren && (
            <ChevronRight className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}`} />
          )}
        </div>
      </div>

      {hasChildren && isOpen && (
        <div className="flex flex-col gap-1 mt-1">
          {item.children!.map((child) => (
            <NavItem
              key={child.id}
              item={child}
              activeId={activeId}
              onSelect={onSelect}
              level={level + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export const SidebarNav: React.FC = () => {
  const {
    currentTab,
    setCurrentTab,
    currentDecision,
    logout,
    investigations,
    setActiveInvestigation,
    evidenceList,
    setSelectedEvidence,
    findings
  } = useInvestigationStore();

  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const navGroups: NavGroupData[] = [
    {
      items: [
        { id: 'search', title: 'Global Search', icon: Search, shortcut: '⌘K' },
        { id: 'home', title: 'Home Dashboard', icon: LayoutDashboard },
      ]
    },
    {
      heading: 'Investigation Workflow',
      items: [
        { id: 'cases', title: 'Cases Studio', icon: FolderKanban },
        { id: 'evidence', title: 'Evidence Ingestion', icon: HardDrive },
        { id: 'process', title: 'Execution Engine', icon: Activity },
        { id: 'results', title: 'Results Matrix', icon: Layers },
        { id: 'ai-analysis', title: 'AI Reasoning', icon: Sparkles },
        { id: 'review', title: 'Decision Gate', icon: ShieldCheck, badge: currentDecision?.decision },
        { id: 'reports', title: 'Reports Studio', icon: FileText },
      ]
    },
    {
      heading: 'Workstation Support',
      items: [
        { id: 'history', title: 'Audit History', icon: Clock },
        { id: 'ai-provider', title: 'AI Provider', icon: Sparkles },
        { id: 'profile', title: 'User Profile', icon: User },
        { id: 'settings', title: 'System Settings', icon: Settings, shortcut: '⌘,' },
      ]
    }
  ];

  const handleSelect = (id: string) => {
    if (id === 'search') {
      setIsSearchOpen(true);
      return;
    }
    setCurrentTab(id);
  };

  // Real Search Across Workspace Store Data
  const searchResults = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return null;

    const matchedCases = investigations.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        (c.case_number && c.case_number.toLowerCase().includes(q)) ||
        (c.objective && c.objective.toLowerCase().includes(q)) ||
        c.id.toLowerCase().includes(q)
    );

    const matchedEvidence = evidenceList.filter(
      (e) =>
        e.name.toLowerCase().includes(q) ||
        e.sha256.toLowerCase().includes(q) ||
        e.evidence_type.toLowerCase().includes(q)
    );

    const matchedFindings = findings.filter(
      (f) =>
        f.title.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.finding_type.toLowerCase().includes(q) ||
        f.verification_status.toLowerCase().includes(q)
    );

    const matchedNav = navGroups
      .flatMap((g) => g.items)
      .filter((item) => item.id !== 'search' && item.title.toLowerCase().includes(q));

    return {
      cases: matchedCases,
      evidence: matchedEvidence,
      findings: matchedFindings,
      nav: matchedNav,
      totalCount: matchedCases.length + matchedEvidence.length + matchedFindings.length + matchedNav.length
    };
  }, [searchQuery, investigations, evidenceList, findings, navGroups]);

  return (
    <aside className="w-64 bg-slate-950/80 backdrop-blur-md border-r border-slate-800/80 flex flex-col justify-between p-3 font-sans select-none shrink-0 z-20">
      <div className="flex-1 overflow-y-auto space-y-4">
        {/* Brand Header */}
        <div className="px-2 py-2 flex items-center gap-3 border-b border-slate-800 pb-3">
          <div className="p-2 bg-indigo-600 rounded-xl text-white shadow-xs shadow-indigo-500/20">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h1 className="font-bold text-sm text-slate-100 tracking-wider font-mono">ADFIR</h1>
            <p className="text-[10px] text-slate-400 font-mono">Forensic Workstation</p>
          </div>
        </div>

        <WorkspaceSwitcher />

        {/* Navigation Items */}
        <div className="flex flex-col gap-4">
          {navGroups.map((group, idx) => (
            <div key={idx} className="flex flex-col gap-1">
              {group.heading && (
                <span className="px-3 mb-1 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                  {group.heading}
                </span>
              )}
              {group.items.map((item) => (
                <NavItem
                  key={item.id}
                  item={item}
                  activeId={currentTab}
                  onSelect={handleSelect}
                />
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Footer Controls & Logout */}
      <div className="pt-3 border-t border-slate-800 flex flex-col gap-2">
        <div className="flex items-center justify-between px-2 text-[10px] font-mono text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Core Ready
          </span>
          <span>v0.1.0</span>
        </div>
        <button
          onClick={logout}
          className="w-full flex items-center justify-center gap-2 py-2 bg-slate-900/60 hover:bg-rose-500/20 hover:text-rose-300 hover:border-rose-500/30 text-slate-300 rounded-xl border border-slate-800 transition-colors text-xs font-semibold"
        >
          <LogOut className="w-3.5 h-3.5" />
          <span>Sign Out Session</span>
        </button>
      </div>

      {/* Real Command Palette / Search Modal */}
      {isSearchOpen && (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] bg-slate-950/80 backdrop-blur-sm px-4">
          <div className="fixed inset-0" onClick={() => setIsSearchOpen(false)} />
          <div className="relative w-full max-w-xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden font-sans text-slate-100 z-10 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center px-4 border-b border-slate-800">
              <Search className="w-4 h-4 text-slate-400 mr-3 shrink-0" />
              <input
                autoFocus
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="flex-1 bg-transparent py-4 outline-none text-sm text-slate-100 placeholder:text-slate-500 font-mono"
                placeholder="Search real cases, SHA-256 hashes, findings, or navigate..."
              />
              <button
                onClick={() => setIsSearchOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-200 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="max-h-[380px] overflow-y-auto p-3 space-y-3">
              {searchResults ? (
                searchResults.totalCount === 0 ? (
                  <div className="py-8 text-center text-xs font-mono text-slate-500">
                    No matching cases, evidence artifacts, or commands found for &ldquo;{searchQuery}&rdquo;.
                  </div>
                ) : (
                  <>
                    {searchResults.cases.length > 0 && (
                      <div>
                        <span className="px-2 text-[10px] font-mono text-slate-400 uppercase font-bold block mb-1">
                          Cases ({searchResults.cases.length})
                        </span>
                        {searchResults.cases.map((c) => (
                          <div
                            key={c.id}
                            onClick={() => {
                              setActiveInvestigation(c);
                              setCurrentTab('cases');
                              setIsSearchOpen(false);
                            }}
                            className="p-2.5 hover:bg-slate-800/60 rounded-xl cursor-pointer flex items-center justify-between transition-colors"
                          >
                            <div className="min-w-0">
                              <span className="text-xs font-semibold text-slate-200 block truncate">{c.name}</span>
                              <span className="text-[10px] text-slate-400 font-mono">{c.case_number || c.id}</span>
                            </div>
                            <span className="text-[10px] font-mono text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20 font-semibold">
                              {c.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}

                    {searchResults.evidence.length > 0 && (
                      <div>
                        <span className="px-2 text-[10px] font-mono text-slate-400 uppercase font-bold block mb-1">
                          Evidence Artifacts ({searchResults.evidence.length})
                        </span>
                        {searchResults.evidence.map((ev) => (
                          <div
                            key={ev.id}
                            onClick={() => {
                              setSelectedEvidence(ev);
                              setCurrentTab('evidence');
                              setIsSearchOpen(false);
                            }}
                            className="p-2.5 hover:bg-slate-800/60 rounded-xl cursor-pointer flex items-center justify-between transition-colors"
                          >
                            <div className="min-w-0 pr-2">
                              <span className="text-xs font-semibold text-slate-200 block truncate">{ev.name}</span>
                              <span className="text-[10px] text-slate-400 font-mono truncate block">{ev.sha256}</span>
                            </div>
                            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20 shrink-0 font-semibold">
                              {ev.evidence_type}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}

                    {searchResults.findings.length > 0 && (
                      <div>
                        <span className="px-2 text-[10px] font-mono text-slate-400 uppercase font-bold block mb-1">
                          Findings ({searchResults.findings.length})
                        </span>
                        {searchResults.findings.map((f) => (
                          <div
                            key={f.id}
                            onClick={() => {
                              setCurrentTab('results');
                              setIsSearchOpen(false);
                            }}
                            className="p-2.5 hover:bg-slate-800/60 rounded-xl cursor-pointer flex items-center justify-between transition-colors"
                          >
                            <div className="min-w-0 pr-2">
                              <span className="text-xs font-semibold text-slate-200 block truncate">{f.title}</span>
                              <span className="text-[10px] text-slate-400 truncate block">{f.description}</span>
                            </div>
                            <span className="text-[10px] font-mono text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20 shrink-0 font-semibold">
                              {f.verification_status}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}

                    {searchResults.nav.length > 0 && (
                      <div>
                        <span className="px-2 text-[10px] font-mono text-slate-400 uppercase font-bold block mb-1">
                          Navigation
                        </span>
                        {searchResults.nav.map((item) => (
                          <div
                            key={item.id}
                            onClick={() => {
                              setCurrentTab(item.id);
                              setIsSearchOpen(false);
                            }}
                            className="p-2.5 hover:bg-slate-800/60 rounded-xl cursor-pointer flex items-center gap-2.5 text-xs text-slate-300 transition-colors"
                          >
                            <item.icon className="w-4 h-4 text-indigo-400" />
                            <span>Navigate to {item.title}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )
              ) : (
                <div className="p-4 space-y-2">
                  <span className="px-2 text-[10px] font-mono text-slate-400 uppercase font-bold block">
                    Quick Navigation
                  </span>
                  {[
                    { id: 'cases', label: 'Go to Cases Studio' },
                    { id: 'evidence', label: 'Go to Evidence Ingestion' },
                    { id: 'process', label: 'Launch Execution Engine' },
                    { id: 'results', label: 'View Results Matrix' },
                    { id: 'reports', label: 'Open Reports Studio' },
                  ].map((act) => (
                    <div
                      key={act.id}
                      onClick={() => {
                        setCurrentTab(act.id);
                        setIsSearchOpen(false);
                      }}
                      className="p-2 hover:bg-slate-800/60 rounded-lg cursor-pointer text-xs font-mono text-slate-300 flex items-center justify-between"
                    >
                      <span>{act.label}</span>
                      <Command className="w-3.5 h-3.5 text-slate-400" />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </aside>
  );
};
