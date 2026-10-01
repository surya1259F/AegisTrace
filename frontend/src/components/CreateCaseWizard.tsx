import React, { useState } from 'react';
import {
  FolderPlus,
  Shield,
  UserPlus,
  Trash2,
  CheckCircle,
  FolderCheck,
  AlertCircle,
  FileText,
  Target,
  Sparkles,
  ArrowRight,
  ArrowLeft,
  X,
  Lock
} from 'lucide-react';
import { api } from '../services/api';
import type { Case, CaseCreateRequest, CaseMemberCreateRequest } from '../types';

interface CreateCaseWizardProps {
  isOpen: boolean;
  onClose: () => void;
  onCaseCreated: (newCase: Case) => void;
}

const DEFAULT_PERMISSIONS = {
  view_case: true,
  edit_case_details: true,
  manage_members: true,
  manage_case_settings: true,
  add_evidence: true,
  run_investigation: true,
  view_findings: true,
  export_report: true,
};

export const CreateCaseWizard: React.FC<CreateCaseWizardProps> = ({
  isOpen,
  onClose,
  onCaseCreated
}) => {
  const [step, setStep] = useState<number>(1);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Form State
  const [title, setTitle] = useState<string>('');
  const [caseNumber, setCaseNumber] = useState<string>('');
  const [caseType, setCaseType] = useState<string>('INCIDENT_RESPONSE');
  const [priority, setPriority] = useState<string>('HIGH');
  const [objective, setObjective] = useState<string>('');
  const [description, setDescription] = useState<string>('');
  const [members, setMembers] = useState<CaseMemberCreateRequest[]>([]);
  const [permissions, setPermissions] = useState<Record<string, boolean>>(DEFAULT_PERMISSIONS);

  // Member Input State
  const [newMemberEmail, setNewMemberEmail] = useState<string>('');
  const [newMemberRole, setNewMemberRole] = useState<string>('COLLABORATOR');

  if (!isOpen) return null;

  const handleAddMember = () => {
    if (!newMemberEmail || !newMemberEmail.trim()) return;
    const cleanEmail = newMemberEmail.trim().toLowerCase();
    if (members.some((m) => m.email === cleanEmail)) {
      setError('Member already added to initial team.');
      return;
    }
    setMembers([...members, { email: cleanEmail, role: newMemberRole }]);
    setNewMemberEmail('');
    setNewMemberRole('COLLABORATOR');
    setError(null);
  };

  const handleRemoveMember = (index: number) => {
    setMembers(members.filter((_, i) => i !== index));
  };

  const togglePermission = (key: string) => {
    setPermissions((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const validateCurrentStep = (): boolean => {
    setError(null);
    if (step === 1) {
      if (!title.trim()) {
        setError('Case title is required.');
        return false;
      }
    } else if (step === 2) {
      if (!objective.trim()) {
        setError('Investigation objective is required.');
        return false;
      }
    }
    return true;
  };

  const handleNext = () => {
    if (validateCurrentStep()) {
      setStep((prev) => Math.min(prev + 1, 7));
    }
  };

  const handleBack = () => {
    setError(null);
    setStep((prev) => Math.max(prev - 1, 1));
  };

  const handleSubmit = async () => {
    if (!validateCurrentStep()) return;
    setIsSubmitting(true);
    setError(null);

    const payload: CaseCreateRequest = {
      title: title.trim(),
      case_number: caseNumber.trim() || undefined,
      case_type: caseType,
      priority,
      objective: objective.trim(),
      description: description.trim() || undefined,
      case_permissions: permissions,
      members: members.length > 0 ? members : undefined,
    };

    try {
      const createdCase = await api.createCase(payload);
      onCaseCreated(createdCase);
      onClose();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Failed to create case workspace.';
      setError(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-800/80 border-b border-slate-700/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <FolderPlus className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100">Create New Forensic Case</h2>
              <p className="text-xs text-slate-400">Step {step} of 7 — Case Initialization Wizard</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-slate-950 h-1.5 flex">
          {[1, 2, 3, 4, 5, 6, 7].map((s) => (
            <div
              key={s}
              className={`h-full flex-1 transition-all duration-300 ${
                s <= step ? 'bg-cyan-500' : 'bg-slate-800'
              }`}
            />
          ))}
        </div>

        {/* Form Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {error && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-start gap-3">
              <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
              <div>{error}</div>
            </div>
          )}

          {/* STEP 1: Details */}
          {step === 1 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-cyan-400 text-sm font-semibold mb-2">
                <FileText className="w-4 h-4" /> Basic Case Details
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                  Case Title <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. Operation Apex Cyber Intrusion"
                  className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 text-sm"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                    Case Number (Optional)
                  </label>
                  <input
                    type="text"
                    value={caseNumber}
                    onChange={(e) => setCaseNumber(e.target.value)}
                    placeholder="Auto-generated if empty"
                    className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 text-sm"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                    Case Type
                  </label>
                  <select
                    value={caseType}
                    onChange={(e) => setCaseType(e.target.value)}
                    className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-slate-100 focus:outline-none focus:border-cyan-500 text-sm"
                  >
                    <option value="INCIDENT_RESPONSE">Incident Response</option>
                    <option value="DIGITAL_FORENSICS">Digital Forensics</option>
                    <option value="MALWARE_ANALYSIS">Malware Analysis</option>
                    <option value="INSIDER_THREAT">Insider Threat</option>
                    <option value="GENERAL_INVESTIGATION">General Investigation</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                    Priority
                  </label>
                  <select
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                    className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-slate-100 focus:outline-none focus:border-cyan-500 text-sm"
                  >
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                    <option value="CRITICAL">Critical</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* STEP 2: Objective */}
          {step === 2 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-cyan-400 text-sm font-semibold mb-2">
                <Target className="w-4 h-4" /> Investigation Objective
              </div>
              <p className="text-xs text-slate-400">
                Define the primary technical or forensic goal for this investigation. This guides AI assistance and specialist evidence correlation.
              </p>
              <div>
                <textarea
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                  rows={4}
                  placeholder="e.g. Determine initial access vector, scope lateral movement, identify exfiltrated files, and isolate compromised domain controllers."
                  className="w-full px-4 py-3 bg-slate-950 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 text-sm resize-none"
                />
              </div>
            </div>
          )}

          {/* STEP 3: Description */}
          {step === 3 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-cyan-400 text-sm font-semibold mb-2">
                <FileText className="w-4 h-4" /> Detailed Investigation Description
              </div>
              <p className="text-xs text-slate-400">
                Provide operational context, incident ticket references, affected hostnames, or legal scope details.
              </p>
              <div>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={5}
                  placeholder="Enter detailed background notes, affected infrastructure IDs, suspect usernames, or chain-of-custody requirements..."
                  className="w-full px-4 py-3 bg-slate-950 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 text-sm resize-none"
                />
              </div>
            </div>
          )}

          {/* STEP 4: Initial Members */}
          {step === 4 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-cyan-400 text-sm font-semibold mb-2">
                <UserPlus className="w-4 h-4" /> Case Members & Team Allocation
              </div>
              <p className="text-xs text-slate-400">
                Assign secondary investigators or analysts to this case. Creator is automatically assigned as Primary Investigator.
              </p>

              <div className="flex gap-3">
                <input
                  type="email"
                  value={newMemberEmail}
                  onChange={(e) => setNewMemberEmail(e.target.value)}
                  placeholder="investigator@org.local"
                  className="flex-1 px-4 py-2 bg-slate-950 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 text-sm"
                />
                <select
                  value={newMemberRole}
                  onChange={(e) => setNewMemberRole(e.target.value)}
                  className="px-4 py-2 bg-slate-950 border border-slate-700/80 rounded-xl text-slate-100 text-sm focus:outline-none focus:border-cyan-500"
                >
                  <option value="CASE_ADMIN">Case Admin</option>
                  <option value="INVESTIGATOR">Investigator</option>
                  <option value="ANALYST">Analyst</option>
                  <option value="COLLABORATOR">Collaborator</option>
                  <option value="VIEWER">Viewer</option>
                </select>
                <button
                  type="button"
                  onClick={handleAddMember}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-xl text-sm transition-colors"
                >
                  Add Member
                </button>
              </div>

              <div className="space-y-2 mt-3">
                {members.length === 0 ? (
                  <div className="text-xs text-slate-500 italic p-4 bg-slate-950/50 rounded-xl border border-slate-800 text-center">
                    No additional team members added. Creator will be sole Primary Investigator.
                  </div>
                ) : (
                  members.map((m, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-3 bg-slate-950 rounded-xl border border-slate-800 text-sm"
                    >
                      <div className="flex items-center gap-3">
                        <span className="font-medium text-slate-200">{m.email}</span>
                        <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          {m.role}
                        </span>
                      </div>
                      <button
                        onClick={() => handleRemoveMember(idx)}
                        className="text-slate-500 hover:text-red-400 transition-colors p-1"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* STEP 5: Case Permissions */}
          {step === 5 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-cyan-400 text-sm font-semibold mb-2">
                <Shield className="w-4 h-4" /> Case Granular Permissions Matrix
              </div>
              <p className="text-xs text-slate-400">
                Configure case-level operational capabilities. These rule boundaries are strictly enforced on all case endpoints.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {Object.entries(permissions).map(([perm, enabled]) => (
                  <div
                    key={perm}
                    onClick={() => togglePermission(perm)}
                    className={`flex items-center justify-between p-3.5 rounded-xl border cursor-pointer transition-all ${
                      enabled
                        ? 'bg-cyan-500/5 border-cyan-500/30 text-slate-200'
                        : 'bg-slate-950 border-slate-800 text-slate-400'
                    }`}
                  >
                    <span className="text-xs font-mono font-medium">{perm}</span>
                    <input
                      type="checkbox"
                      checked={enabled}
                      onChange={() => togglePermission(perm)}
                      className="w-4 h-4 rounded text-cyan-500 focus:ring-cyan-500"
                    />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* STEP 6: Workspace Pre-flight */}
          {step === 6 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-cyan-400 text-sm font-semibold mb-2">
                <FolderCheck className="w-4 h-4" /> Workspace Disk Isolation Verification
              </div>
              <p className="text-xs text-slate-400">
                ADFIR will automatically provision an isolated directory structure on local disk under the configured root data path.
              </p>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-3">
                <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">
                  Standard Directory Substructures
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono text-cyan-300">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> evidence/
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> forensic_outputs/
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> analysis/
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> findings/
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> reports/
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> logs/
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800 text-xs text-slate-400 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-emerald-400" /> Path Traversal &amp; Null Byte Guards Enabled
                </div>
              </div>
            </div>
          )}

          {/* STEP 7: Review & Confirm */}
          {step === 7 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-cyan-400 text-sm font-semibold mb-2">
                <Sparkles className="w-4 h-4" /> Review &amp; Initialize Case
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3 text-sm">
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400">Title:</span>
                  <span className="font-semibold text-slate-100">{title}</span>
                </div>
                {caseNumber && (
                  <div className="flex justify-between border-b border-slate-800 pb-2">
                    <span className="text-slate-400">Case Number:</span>
                    <span className="font-mono text-cyan-400">{caseNumber}</span>
                  </div>
                )}
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400">Type &amp; Priority:</span>
                  <span className="text-slate-200">{caseType} — {priority}</span>
                </div>
                <div className="border-b border-slate-800 pb-2">
                  <span className="text-slate-400 block mb-1">Objective:</span>
                  <span className="text-slate-200 text-xs italic">{objective}</span>
                </div>
                <div>
                  <span className="text-slate-400 block mb-1">Team Members:</span>
                  <span className="text-slate-200 text-xs">
                    {members.length === 0
                      ? 'Sole Primary Investigator (Case Owner)'
                      : `${members.length + 1} Investigators & Analysts`}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer Navigation */}
        <div className="px-6 py-4 bg-slate-800/80 border-t border-slate-700/60 flex items-center justify-between">
          <button
            type="button"
            onClick={handleBack}
            disabled={step === 1 || isSubmitting}
            className={`px-4 py-2 rounded-xl text-sm font-medium flex items-center gap-2 transition-colors ${
              step === 1 || isSubmitting
                ? 'opacity-40 cursor-not-allowed text-slate-500'
                : 'text-slate-300 hover:text-white hover:bg-slate-700'
            }`}
          >
            <ArrowLeft className="w-4 h-4" /> Back
          </button>

          {step < 7 ? (
            <button
              type="button"
              onClick={handleNext}
              className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-xl text-sm flex items-center gap-2 transition-colors shadow-lg shadow-cyan-900/20"
            >
              Next Step <ArrowRight className="w-4 h-4" />
            </button>
          ) : (
            <button
              type="button"
              onClick={handleSubmit}
              disabled={isSubmitting}
              className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-xl text-sm flex items-center gap-2 transition-colors shadow-lg shadow-emerald-900/30"
            >
              {isSubmitting ? (
                <span>Initializing Workspace...</span>
              ) : (
                <>
                  <FolderCheck className="w-4 h-4" /> Create Case Workspace
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
