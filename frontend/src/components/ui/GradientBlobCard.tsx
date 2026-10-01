import React from 'react';

export interface GradientBlobCardProps {
  children?: React.ReactNode;
  className?: string;
  onClick?: () => void;
}

export const GradientBlobCard: React.FC<GradientBlobCardProps> = ({
  children,
  className = "",
  onClick,
}) => {
  return (
    <div 
      onClick={onClick}
      className={`relative rounded-xl overflow-hidden p-6 bg-slate-900/80 border border-slate-800 shadow-xl backdrop-blur-xl ${className}`}
    >
      <div className="absolute -top-10 -left-10 w-40 h-40 rounded-full opacity-30 filter blur-2xl animate-pulse bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 pointer-events-none" />
      <div className="absolute -bottom-10 -right-10 w-40 h-40 rounded-full opacity-20 filter blur-2xl animate-pulse bg-gradient-to-r from-blue-600 to-emerald-500 pointer-events-none" />
      <div className="relative z-10">{children}</div>
    </div>
  );
};

export default GradientBlobCard;
