import React from "react";

interface SidebarProps {
  collapsed: boolean;
  activeProject: string;
  onSelectProject: (name: string) => void;
  onNewAnalysis: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed,
  activeProject,
  onSelectProject,
  onNewAnalysis,
}) => {
  const recentProjects = [
    { name: "vulnerable-api" },
    { name: "LumiDesk" },
    { name: "authentication-service" },
  ];

  if (collapsed) return null;

  return (
    <aside className="w-[240px] bg-[#0e0e0e] border-r border-[#222222] flex flex-col flex-shrink-0 select-none">
      {/* Brand Header */}
      <div className="p-4 border-b border-[#222222] flex items-center gap-3">
        <div className="w-6 h-6 rounded bg-[#1a1a1a] border border-[#2e2e2e] flex items-center justify-center font-bold text-xs text-white">
          V
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-bold tracking-wider text-white">VAJRA</span>
          <span className="text-[10px] font-semibold text-neutral-500 tracking-widest uppercase">SECURITY ENGINE</span>
        </div>
      </div>

      {/* New Analysis Action */}
      <button
        onClick={onNewAnalysis}
        className="m-3 p-2 rounded bg-[#141414] border border-[#222222] hover:border-[#3e3e3e] text-xs font-semibold text-neutral-200 flex items-center gap-2 transition"
      >
        <span className="text-sm text-white">+</span> New Analysis
      </button>

      {/* Recent Projects */}
      <div className="px-3 py-2 text-[10px] font-bold text-neutral-500 uppercase tracking-wider">Recent</div>
      <div className="flex-1 overflow-y-auto px-2 space-y-1">
        {recentProjects.map((p) => (
          <button
            key={p.name}
            onClick={() => onSelectProject(p.name)}
            className={`w-full text-left flex items-center gap-2.5 px-2.5 py-1.5 rounded text-xs transition ${
              activeProject === p.name
                ? "bg-[#1b1b1b] text-white font-semibold relative before:absolute before:left-0 before:top-2 before:bottom-2 before:w-0.5 before:bg-white"
                : "text-neutral-400 hover:bg-[#141414] hover:text-neutral-200"
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-neutral-600" />
            <span className="truncate">{p.name}</span>
          </button>
        ))}
      </div>

      {/* Footer System Status */}
      <div className="p-3 border-t border-[#222222] text-xs space-y-1">
        <div className="flex items-center gap-2 text-neutral-400 font-medium">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          <span>6/6 Verifiers Ready</span>
        </div>
        <div className="text-[11px] text-neutral-500">100% Offline Autonomous Mode</div>
      </div>
    </aside>
  );
};
