import React, { useEffect } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { AuthModal } from './AuthModal';
import { HomePage } from '../pages/HomePage';
import { InvestigationPage } from '../pages/InvestigationPage';
import { EvidencePage } from '../pages/EvidencePage';
import { InvestigationProcessPage } from '../pages/InvestigationProcessPage';
import { ResultsPage } from '../pages/ResultsPage';
import { AIAnalysisPage } from '../pages/AIAnalysisPage';
import { InvestigatorReviewPage } from '../pages/InvestigatorReviewPage';
import { ReportsPage } from '../pages/ReportsPage';
import { HistoryPage } from '../pages/HistoryPage';
import { AIProviderPage } from '../pages/AIProviderPage';
import { ProfilePage } from '../pages/ProfilePage';
import { SettingsPage } from '../pages/SettingsPage';
import { useInvestigationStore } from '../stores/investigationStore';
import { ShieldAlert, Loader2 } from 'lucide-react';
import { AuroraBackground } from './ui/AuroraBackground';
import { DiaText } from './ui/DiaText';

export const AppShell: React.FC = () => {
  const {
    currentTab,
    authStatus,
    backendState,
    backendError,
    initializeBackend,
    restoreSession,
    fetchInvestigations,
    fetchSystemStatus,
    setAuthModalOpen
  } = useInvestigationStore();

  useEffect(() => {
    initializeBackend();
  }, [initializeBackend]);

  useEffect(() => {
    if (backendState === 'READY') {
      restoreSession();
    }
  }, [backendState, restoreSession]);

  useEffect(() => {
    if (backendState === 'READY' && authStatus === 'AUTHENTICATED') {
      fetchSystemStatus();
      fetchInvestigations();
    }
  }, [backendState, authStatus, fetchInvestigations, fetchSystemStatus]);

  if (backendState === 'DISCOVERING') {
    return (
      <AuroraBackground className="h-screen w-screen select-none font-mono flex items-center justify-center">
        <div className="p-8 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl shadow-2xl flex flex-col items-center justify-center space-y-4 max-w-sm w-full mx-4">
          <div className="p-3 bg-indigo-950/60 border border-indigo-800/60 rounded-2xl text-indigo-400">
            <Loader2 className="w-8 h-8 animate-spin" />
          </div>
          <div className="text-center space-y-1">
            <h2 className="text-sm font-bold tracking-widest text-slate-100">ADFIR WORKSTATION</h2>
            <p className="text-xs text-slate-400">INITIALIZING DESKTOP BACKEND DISCOVERY...</p>
          </div>
        </div>
      </AuroraBackground>
    );
  }

  if (backendState === 'STOPPING') {
    return (
      <AuroraBackground className="h-screen w-screen select-none font-mono flex items-center justify-center">
        <div className="p-8 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl shadow-2xl flex flex-col items-center justify-center space-y-4 max-w-sm w-full mx-4">
          <div className="p-3 bg-amber-950/60 border border-amber-800/60 rounded-2xl text-amber-400">
            <Loader2 className="w-8 h-8 animate-spin" />
          </div>
          <div className="text-center space-y-1">
            <h2 className="text-sm font-bold tracking-widest text-slate-100">ADFIR WORKSTATION</h2>
            <p className="text-xs text-amber-400">SHUTTING DOWN DESKTOP SERVICE...</p>
          </div>
        </div>
      </AuroraBackground>
    );
  }

  if (backendState === 'UNAVAILABLE' || backendState === 'CRASHED') {
    return (
      <AuroraBackground className="h-screen w-screen select-none font-mono flex items-center justify-center p-6">
        <div className="max-w-md w-full text-center space-y-6 p-8 rounded-2xl bg-slate-900/95 border border-red-900/50 backdrop-blur-xl shadow-2xl">
          <div className="inline-flex p-4 bg-red-950/40 border border-red-800/60 rounded-3xl text-red-400 mb-2">
            <ShieldAlert className="w-10 h-10" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-wider text-slate-100">DESKTOP BACKEND SERVICE UNAVAILABLE</h1>
            <p className="text-xs text-red-400 mt-2">{backendError || 'Failed to establish secure communication with local ADFIR backend service.'}</p>
          </div>
          <button
            onClick={() => initializeBackend()}
            className="w-full py-3 bg-red-600 hover:bg-red-500 text-white rounded-xl font-bold tracking-wide shadow-lg shadow-red-500/25 transition-all text-xs"
          >
            RETRY BACKEND DISCOVERY
          </button>
        </div>
      </AuroraBackground>
    );
  }

  if (authStatus === 'RESTORING') {
    return (
      <AuroraBackground className="h-screen w-screen select-none font-mono flex items-center justify-center">
        <div className="p-8 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl shadow-2xl flex flex-col items-center justify-center space-y-4 max-w-sm w-full mx-4">
          <div className="p-3 bg-indigo-950/60 border border-indigo-800/60 rounded-2xl text-indigo-400">
            <Loader2 className="w-8 h-8 animate-spin" />
          </div>
          <div className="text-center space-y-1">
            <h2 className="text-sm font-bold tracking-widest text-slate-100">ADFIR WORKSTATION</h2>
            <p className="text-xs text-slate-400">VERIFYING AUTHENTICATED SESSION...</p>
          </div>
        </div>
      </AuroraBackground>
    );
  }

  if (authStatus === 'UNAUTHENTICATED') {
    return (
      <AuroraBackground className="h-screen w-screen select-none font-mono flex items-center justify-center p-6">
        <div className="max-w-md w-full text-center space-y-6 p-8 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl shadow-2xl">
          <div className="inline-flex p-4 bg-indigo-950/60 border border-indigo-800/60 rounded-3xl shadow-xs text-indigo-400 mb-1">
            <ShieldAlert className="w-10 h-10" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wider text-slate-100">
              <DiaText text="ADFIR FORENSIC WORKSTATION" colors={['#ffffff', '#a5b4fc', '#818cf8', '#c7d2fe']} />
            </h1>
            <p className="text-xs text-slate-400 mt-2">AUTHENTICATION REQUIRED FOR CASE ACCESS</p>
          </div>
          <button
            onClick={() => setAuthModalOpen(true)}
            className="w-full py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-bold tracking-wide shadow-lg shadow-indigo-500/25 transition-all text-xs"
          >
            AUTHENTICATE INVESTIGATOR SESSION
          </button>
        </div>
        <AuthModal />
      </AuroraBackground>
    );
  }

  const renderPage = () => {
    switch (currentTab) {
      case 'home':
        return <HomePage />;
      case 'cases':
        return <InvestigationPage />;
      case 'evidence':
        return <EvidencePage />;
      case 'process':
      case 'investigation':
      case 'analysis':
        return <InvestigationProcessPage />;
      case 'results':
      case 'findings':
        return <ResultsPage />;
      case 'ai-analysis':
        return <AIAnalysisPage />;
      case 'review':
        return <InvestigatorReviewPage />;
      case 'reports':
        return <ReportsPage />;
      case 'history':
        return <HistoryPage />;
      case 'ai-provider':
        return <AIProviderPage />;
      case 'profile':
        return <ProfilePage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return <HomePage />;
    }
  };

  return (
    <AuroraBackground className="h-screen w-screen overflow-hidden select-none font-sans" showRadialGradient={true}>
      <div className="flex h-full w-full min-w-0 overflow-hidden">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden bg-slate-950/40 backdrop-blur-md">
          <TopBar />
          <main className="flex-1 p-6 overflow-y-auto bg-transparent">
            {renderPage()}
          </main>
        </div>
      </div>
      <AuthModal />
    </AuroraBackground>
  );
};

