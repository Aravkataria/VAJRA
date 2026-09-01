import React from "react";

interface HeroEmptyStateProps {
  onScanProject: () => void;
  onOpenFolder: () => void;
  onAttachZip: () => void;
  onExplainPipeline: () => void;
}

export const HeroEmptyState: React.FC<HeroEmptyStateProps> = ({
  onScanProject,
  onOpenFolder,
  onAttachZip,
  onExplainPipeline,
}) => {
  return (
    <div className="m-auto max-w-[600px] text-center flex flex-col items-center py-8">
      <div className="text-lg font-bold text-white tracking-wider mb-2">
        VAJRA
      </div>
      <h1 className="text-2xl font-bold text-white tracking-tight mb-2">
        Autonomous Security Intelligence
      </h1>
      <p className="text-sm text-neutral-400 max-w-[460px] leading-relaxed mb-6">
        Analyze your codebase, identify vulnerabilities, generate minimal repairs, and independently verify the result.
      </p>

      <div className="flex flex-wrap gap-2 justify-center mb-6">
        <button
          onClick={onScanProject}
          className="px-3.5 py-1.5 rounded-full bg-[#141414] border border-[#222222] hover:border-[#3e3e3e] hover:text-white text-xs font-medium text-neutral-300 transition"
        >
          Scan Demo Project
        </button>
        <button
          onClick={onOpenFolder}
          className="px-3.5 py-1.5 rounded-full bg-[#141414] border border-[#222222] hover:border-[#3e3e3e] hover:text-white text-xs font-medium text-neutral-300 transition"
        >
          Local Folder
        </button>
        <button
          onClick={onAttachZip}
          className="px-3.5 py-1.5 rounded-full bg-[#141414] border border-[#222222] hover:border-[#3e3e3e] hover:text-white text-xs font-medium text-neutral-300 transition"
        >
          Attach ZIP
        </button>
        <button
          onClick={onExplainPipeline}
          className="px-3.5 py-1.5 rounded-full bg-[#141414] border border-[#222222] hover:border-[#3e3e3e] hover:text-white text-xs font-medium text-neutral-300 transition"
        >
          Verification Pipeline
        </button>
      </div>
    </div>
  );
};
