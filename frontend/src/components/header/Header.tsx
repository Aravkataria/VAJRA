import React from "react";

interface HeaderProps {
  projectName: string;
  status: string;
  activeTab: "chat" | "security" | "repairs" | "verification" | "report";
  onTabChange: (tab: "chat" | "security" | "repairs" | "verification" | "report") => void;
  onToggleSidebar: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  projectName,
  status,
  activeTab,
  onTabChange,
  onToggleSidebar,
}) => {
  const tabs: { id: typeof activeTab; label: string }[] = [
    { id: "chat", label: "Chat" },
    { id: "security", label: "Security" },
    { id: "repairs", label: "Repairs" },
    { id: "verification", label: "Verification" },
    { id: "report", label: "Report" },
  ];

  return (
    <header className="h-[50px] border-b border-white/[0.06] flex items-center justify-between px-6 bg-[#080a11] select-none flex-shrink-0">
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          className="text-slate-400 hover:text-slate-200 p-1 rounded transition"
          title="Toggle Sidebar"
        >
          &#9776;
        </button>
        <div className="flex items-center gap-1.5 text-xs font-medium">
          <span className="text-slate-500 font-semibold">VAJRA</span>
          <span className="text-slate-600">/</span>
          <span className="text-white font-bold">{projectName}</span>
        </div>
        <div className="flex items-center gap-1.5 bg-white/[0.03] border border-white/[0.06] px-2 py-0.5 rounded-full text-[11px] text-slate-400">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          <span>{status}</span>
        </div>
      </div>

      <nav className="flex items-center gap-1 bg-slate-900/80 border border-white/[0.06] p-0.5 rounded-lg">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => onTabChange(t.id)}
            className={`px-3 py-1 rounded text-xs font-semibold transition ${
              activeTab === t.id
                ? "bg-slate-800 text-sky-400 shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>
    </header>
  );
};
