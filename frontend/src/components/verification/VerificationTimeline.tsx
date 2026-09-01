import React from "react";

export const VerificationTimeline: React.FC = () => {
  const steps = [
    { idx: "01", name: "Syntax / AST Validation", status: "Passed" },
    { idx: "02", name: "Static Sink Removal", status: "Passed" },
    { idx: "03", name: "Sentinel Dynamic PoC", status: "Passed" },
    { idx: "04", name: "Regression Test Suites", status: "Passed" },
    { idx: "05", name: "Boundary Fuzzing", status: "Passed" },
    { idx: "06", name: "Patch Mutation Testing", status: "Passed" },
  ];

  return (
    <div className="py-3 flex flex-col gap-2">
      <div className="text-[11px] font-extrabold uppercase tracking-wider text-slate-500">
        ENGINEERING VERIFICATION PIPELINE
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
        {steps.map((s) => (
          <div
            key={s.idx}
            className="flex items-center gap-2 p-2.5 rounded bg-slate-900/60 border border-white/[0.06] text-xs"
          >
            <span className="font-mono text-sky-400 font-bold text-[11px]">{s.idx}</span>
            <span className="text-slate-200 font-medium">{s.name}</span>
            <span className="ml-auto text-emerald-400 font-bold">✓ {s.status}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
