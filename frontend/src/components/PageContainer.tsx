import React from 'react';
import { DiaText } from './ui/DiaText';

interface PageContainerProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
}

export const PageContainer: React.FC<PageContainerProps> = ({ title, subtitle, actions, children }) => {
  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-10">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-1">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            <DiaText
              text={title}
              colors={['#ffffff', '#a5b4fc', '#818cf8', '#c7d2fe']}
              duration={1.4}
              repeat={false}
              className="text-xl font-bold tracking-tight text-slate-100"
            />
          </h2>
          {subtitle && <p className="text-slate-400 text-xs mt-1.5 font-sans leading-relaxed max-w-2xl">{subtitle}</p>}
        </div>
        {actions && <div className="flex items-center gap-2.5 shrink-0 flex-wrap">{actions}</div>}
      </div>
      {children}
    </div>
  );
};

