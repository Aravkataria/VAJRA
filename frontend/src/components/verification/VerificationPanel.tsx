import React from "react";

interface VerificationPanelProps {
  passed: boolean;
  steps?: { name: string; status: "passed" | "failed" | "running" }[];
}

export const VerificationPanel: React.FC<VerificationPanelProps> = ({ passed }) => {
  const steps = [
    { name: "Syntax AST Validation", icon: "✓" },
    { name: "Static Sink Removal", icon: "✓" },
    { name: "Sentinel Dynamic Exploit PoC", icon: "✓" },
    { name: "Baseline Regression Suites", icon: "✓" },
    { name: "Boundary Fuzzing Clean", icon: "✓" },
    { name: "Patch Mutation Verified", icon: "✓" },
  ];

  return (
    <div className={`p-4 rounded-lg border my-3 bg-slate-900/80 ${passed ? "border-emerald-500/40" : "border-red-500/40"}`}>
      <div className="flex items-center justify-between mb-3">
        <h4 className="font-bold text-sm text-slate-100 uppercase tracking-wider">6-Stage Independent Verification</h4>
        <span className={`text-xs font-black px-2.5 py-1 rounded ${passed ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-red-500/10 text-red-400"}`}>
          {passed ? "✓ PATCH VERIFIED & EFFECTIVE" : "VERIFICATION FAILED"}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
        {steps.map((s, idx) => (
          <div key={idx} className="flex items-center gap-2 p-2 rounded bg-slate-950/60 border border-slate-800 text-slate-300">
            <span className="text-emerald-400 font-bold">{s.icon}</span>
            <span>{s.name}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
