export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id?: string;
  file: string;
  line: number;
  vulnerability_type: string;
  message: string;
  function?: string;
  severity?: Severity;
  call_name?: string;
  evidence_chain?: string[];
  confidence?: number;
}

export interface Patch {
  file: string;
  line: number;
  vulnerability_type: string;
  diff: string;
  description?: string;
  confidence?: number;
  strategy?: string;
  call_name?: string;
}

export interface VerificationResult {
  step: string;
  passed: boolean;
  message?: string;
  execution_time_ms?: number;
}

export interface AssuranceReport {
  workspace_id: string;
  summary: {
    initial_findings: number;
    verified_repairs: number;
    structured_non_repairs: number;
  };
  details?: Record<string, any>;
}

export interface ScanResult {
  findings: Finding[];
  patches: Patch[];
  assurance_report?: AssuranceReport;
  verified_count?: number;
  declined_count?: number;
}
