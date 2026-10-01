import * as React from "react";
import { UploadCloud, X, Trash2, ShieldCheck, AlertCircle } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "../../lib/utils";

export interface UploadedFile {
  id: string;
  file: File;
  progress: number; // 0-100
  status: "uploading" | "completed" | "error";
  errorText?: string;
}

interface FileUploadCardProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'onDrag' | 'onDragStart' | 'onDragEnd' | 'onAnimationStart'> {
  files: UploadedFile[];
  onFilesChange: (files: File[]) => void;
  onFileRemove: (id: string) => void;
  onClose?: () => void;
  acceptedTypesLabel?: string;
}

export const FileUploadCard = React.forwardRef<HTMLDivElement, FileUploadCardProps>(
  ({ className, files = [], onFilesChange, onFileRemove, onClose, acceptedTypesLabel, ...props }, ref) => {
    const [isDragging, setIsDragging] = React.useState(false);
    const fileInputRef = React.useRef<HTMLInputElement>(null);

    const handleDragEnter = (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(true);
    };

    const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);
    };

    const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
    };

    const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);
      const droppedFiles = Array.from(e.dataTransfer.files);
      if (droppedFiles && droppedFiles.length > 0) {
        onFilesChange(droppedFiles);
      }
    };

    const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
      const selectedFiles = Array.from(e.target.files || []);
      if (selectedFiles.length > 0) {
        onFilesChange(selectedFiles);
      }
    };

    const triggerFileSelect = () => fileInputRef.current?.click();

    const formatFileSize = (bytes: number) => {
      if (bytes === 0) return "0 KB";
      const k = 1024;
      const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    };
    
    const cardVariants = {
      hidden: { opacity: 0, y: 15 },
      visible: { opacity: 1, y: 0 },
    };
    
    const fileItemVariants = {
      hidden: { opacity: 0, x: -15 },
      visible: { opacity: 1, x: 0 },
    };

    return (
      <motion.div
        ref={ref}
        variants={cardVariants}
        initial="hidden"
        animate="visible"
        transition={{ duration: 0.3 }}
        className={cn(
          "w-full bg-slate-900 border border-slate-800 rounded-xl shadow-xl overflow-hidden font-sans text-slate-100",
          className
        )}
        {...props}
      >
        <div className="p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 flex items-center justify-center rounded-xl bg-indigo-600/20 border border-indigo-500/30 text-indigo-400">
                <UploadCloud className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-100 tracking-wide font-mono">FORENSIC EVIDENCE INGESTION</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Securely upload forensic disk images, PCAP files, or memory dumps for chain-of-custody indexing
                </p>
              </div>
            </div>
            {onClose && (
              <button 
                onClick={onClose}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          <div
            onDragEnter={handleDragEnter}
            onDragLeave={handleDragLeave}
            onDragOver={handleDragOver}
            onDrop={handleDrop}
            onClick={triggerFileSelect}
            className={cn(
              "mt-6 border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center text-center transition-all duration-200 cursor-pointer select-none",
              isDragging
                ? "border-indigo-500 bg-indigo-500/10 shadow-lg shadow-indigo-500/10"
                : "border-slate-800 hover:border-indigo-500/50 hover:bg-slate-800/40"
            )}
          >
            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={handleFileSelect}
            />
            <div className="p-3 bg-slate-800/80 rounded-full border border-slate-700/60 mb-3 text-indigo-400">
              <UploadCloud className="w-8 h-8" />
            </div>
            <p className="font-semibold text-sm text-slate-200">
              Drop forensic artifacts here or <span className="text-indigo-400 underline">browse files</span>
            </p>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              {acceptedTypesLabel || "Supported formats: .E01, .RAW, .DD, .PCAP, .LOG, .MEM, .ZIP"}
            </p>
            <button 
              type="button"
              className="mt-4 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold font-mono rounded-lg shadow-md shadow-indigo-500/20 transition-all pointer-events-none"
            >
              Select Forensic Files
            </button>
          </div>
        </div>
        
        {files.length > 0 && (
          <div className="p-6 border-t border-slate-800 bg-slate-950/40">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-mono uppercase text-slate-400 font-bold tracking-wider">
                Ingested Evidence Queue ({files.length})
              </span>
            </div>
            <ul className="space-y-3">
              <AnimatePresence>
                {files.map((file) => (
                  <motion.li
                    key={file.id}
                    variants={fileItemVariants}
                    initial="hidden"
                    animate="visible"
                    exit="hidden"
                    layout
                    className="flex items-center justify-between p-3 bg-slate-900 border border-slate-800/80 rounded-xl"
                  >
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <div className="w-10 h-10 shrink-0 flex items-center justify-center rounded-lg bg-indigo-950/50 border border-indigo-800/40 text-xs font-mono font-bold text-indigo-300">
                        {file.file.name.split('.').pop()?.toUpperCase().substring(0, 4) || "BIN"}
                      </div>
                      <div className="flex-1 min-w-0 pr-4">
                        <p className="text-xs font-semibold text-slate-200 truncate">{file.file.name}</p>
                        <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono mt-0.5">
                          {file.status === "uploading" && (
                            <span>{formatFileSize((file.file.size * file.progress) / 100)} / {formatFileSize(file.file.size)}</span>
                          )}
                          {file.status === "completed" && (
                            <span>{formatFileSize(file.file.size)}</span>
                          )}
                          <span>•</span>
                          <span className={cn(
                             file.status === 'uploading' ? "text-indigo-400 font-bold" : "",
                             file.status === 'completed' ? "text-emerald-400 font-bold" : "",
                             file.status === 'error' ? "text-rose-400 font-bold" : ""
                          )}>
                            {file.status === 'uploading' ? `Hashed & Indexing ${file.progress}%` : file.status === 'completed' ? 'Chain-of-Custody Verified' : 'Failed'}
                          </span>
                        </div>
                        {file.status === 'uploading' && (
                          <div className="w-full bg-slate-800 rounded-full h-1.5 mt-1.5 overflow-hidden">
                            <div 
                              className="bg-indigo-500 h-1.5 rounded-full transition-all duration-300" 
                              style={{ width: `${file.progress}%` }} 
                            />
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-2 shrink-0">
                      {file.status === 'completed' && (
                        <div className="flex items-center gap-1 text-emerald-400 bg-emerald-950/40 px-2 py-1 rounded-md border border-emerald-800/40 text-[10px] font-mono">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>VERIFIED</span>
                        </div>
                      )}
                      {file.status === 'error' && (
                        <div className="flex items-center gap-1 text-rose-400 bg-rose-950/40 px-2 py-1 rounded-md border border-rose-800/40 text-[10px] font-mono">
                          <AlertCircle className="w-3.5 h-3.5" />
                          <span>ERROR</span>
                        </div>
                      )}
                      <button 
                        onClick={() => onFileRemove(file.id)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                      >
                        {file.status === 'completed' ? <Trash2 className="w-4 h-4" /> : <X className="w-4 h-4" />}
                      </button>
                    </div>
                  </motion.li>
                ))}
              </AnimatePresence>
            </ul>
          </div>
        )}
      </motion.div>
    );
  }
);
FileUploadCard.displayName = "FileUploadCard";
