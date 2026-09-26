# VAJRA Autonomous Security & Quality Audit

> Automated Code Review & Security Ledger
> Conducted by [vajra-bot](https://github.com/apps/vajra-bot) • Zero-Retention Architecture

### Scan Metrics
- **Applied Verified Patches**: 10
- **Remaining Findings (Manual Review)**: 71

### Verified Code Patches Applied

- `app/desktop_app.py` line 99: Active Debug Flag in Production (CWE-489)
- `app/native_gui.py` line 191: Archive Extraction Path Traversal (Tar/Zip Slip) (CWE-22)
- `app/test_repository/vulnerable_pickle.py` line 13: Insecure Deserialization via pickle (CWE-502)
- `app/test_repository/vulnerable_yaml.py` line 12: Unsafe YAML Deserialization (yaml.load) (CWE-502)
- `app/test_repository/vulnerable.py` line 21: Dynamic Code Execution Sink (eval / exec) (CWE-94)
- `kaggle/model1_security_analyst/benchmark_comparative_models.py` line 232: Archive Extraction Path Traversal (Tar/Zip Slip) (CWE-22)
- `kaggle/model1_security_analyst/test_model1_kaggle.py` line 59: Archive Extraction Path Traversal (Tar/Zip Slip) (CWE-22)
- `kaggle/model2_patch_generator/public_benchmarking_model2.py` line 276: Archive Extraction Path Traversal (Tar/Zip Slip) (CWE-22)
- `kaggle/model2_patch_generator/test_model2_kaggle.py` line 84: Archive Extraction Path Traversal (Tar/Zip Slip) (CWE-22)
- `kaggle/model2_patch_generator/benchmark_model2_kaggle.py` line 384: Archive Extraction Path Traversal (Tar/Zip Slip) (CWE-22)

### Detailed Security Ledger

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `check_repair.py` (Line 61)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `backend/server.py` (Line 423)
- **Description**: Accumulating string 'file_summary' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `hf_space/app.py` (Line 494)
- **Description**: Accumulating string 'summary_text' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `hf_space/app.py` (Line 564)
- **Description**: Accumulating string 'summary_text' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `hf_space/app.py` (Line 730)
- **Description**: Accumulating string 'accumulated' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `hf_space/app.py` (Line 767)
- **Description**: Accumulating string 'accumulated' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `hf_space/app.py` (Line 1540)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `hf_space/app.py` (Line 1586)
- **Description**: Accumulating string 'lines' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `hf_space/app.py` (Line 1652)
- **Description**: Accumulating string 'files_scanned' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `hf_space/app.py` (Line 1660)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `hf_space/app.py` (Line 1701)
- **Description**: Accumulating string 'issue_body_lines' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `hf_space/app.py` (Line 1731)
- **Description**: Accumulating string 'audit_md_lines' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `hf_space/app.py` (Line 2026)
- **Description**: Accumulating string 'scanned' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `app/api.py` (Line 817)
- **Description**: Accumulating string 'files_summary' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `scripts/run_local_vajra.py` (Line 49)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `scripts/run_local_vajra.py` (Line 79)
- **Description**: Accumulating string 'full_prompt' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `scripts/chat_cli.py` (Line 123)
- **Description**: Accumulating string 'current_content' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [HIGH] Subprocess Invocation with shell=True (CWE-78)
- **File**: `scripts/vajra_agent_cli.py` (Line 65)
- **Description**: Invoking subprocesses with `shell=True` exposes the application to command injection. Pass an argument list directly with `shell=False`.
- **Remediation**: subprocess.run(['command', arg], shell=False, check=True)

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `scripts/vajra_agent_cli.py` (Line 80)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `vajra_bot/main.py` (Line 136)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `backend/hf_space/app.py` (Line 494)
- **Description**: Accumulating string 'summary_text' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `backend/hf_space/app.py` (Line 564)
- **Description**: Accumulating string 'summary_text' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `backend/hf_space/app.py` (Line 730)
- **Description**: Accumulating string 'accumulated' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `backend/hf_space/app.py` (Line 767)
- **Description**: Accumulating string 'accumulated' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `backend/hf_space/app.py` (Line 1540)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `backend/hf_space/app.py` (Line 1586)
- **Description**: Accumulating string 'lines' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `backend/hf_space/app.py` (Line 1652)
- **Description**: Accumulating string 'files_scanned' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `backend/hf_space/app.py` (Line 1660)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `backend/hf_space/app.py` (Line 1701)
- **Description**: Accumulating string 'issue_body_lines' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `backend/hf_space/app.py` (Line 1731)
- **Description**: Accumulating string 'audit_md_lines' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `backend/hf_space/app.py` (Line 2026)
- **Description**: Accumulating string 'scanned' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `app/models/router.py` (Line 74)
- **Description**: Accumulating string 'total_code_lines' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `app/repository/manager.py` (Line 118)
- **Description**: Accumulating string 'member_count' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `app/repository/manager.py` (Line 125)
- **Description**: Accumulating string 'total_extracted_bytes' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [HIGH] Subprocess Invocation with shell=True (CWE-78)
- **File**: `app/test_repository/test1.py` (Line 4)
- **Description**: Invoking subprocesses with `shell=True` exposes the application to command injection. Pass an argument list directly with `shell=False`.
- **Remediation**: subprocess.run(['command', arg], shell=False, check=True)

#### [HIGH] Subprocess Invocation with shell=True (CWE-78)
- **File**: `app/test_repository/vulnerable.py` (Line 12)
- **Description**: Invoking subprocesses with `shell=True` exposes the application to command injection. Pass an argument list directly with `shell=False`.
- **Remediation**: subprocess.run(['command', arg], shell=False, check=True)

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/dependency_reachability.py` (Line 142)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/cpg_engine.py` (Line 147)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/cpg_engine.py` (Line 235)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/cpg_engine.py` (Line 246)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/cpg_engine.py` (Line 247)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/workspace_scan.py` (Line 36)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/security_ir/extractor.py` (Line 85)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/security_ir/extractor.py` (Line 118)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/security_ir/extractor.py` (Line 223)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/security_ir/extractor.py` (Line 239)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/security_ir/extractor.py` (Line 255)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/security_ir/extractor.py` (Line 300)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `app/analysis/security_ir/extractor.py` (Line 357)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `training/model1_security_analyst/schema.py` (Line 51)
- **Description**: Accumulating string 'user_content' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model1_security_analyst/benchmark_comparative_models.py` (Line 146)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `kaggle/model1_security_analyst/benchmark_comparative_models.py` (Line 149)
- **Description**: Accumulating string 'sample_code' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model1_security_analyst/benchmark_comparative_models.py` (Line 386)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model1_security_analyst/train_model1_kaggle.py` (Line 118)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `kaggle/model1_security_analyst/train_model1_kaggle.py` (Line 119)
- **Description**: Accumulating string 'sample_counter' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model1_security_analyst/train_model1_kaggle.py` (Line 378)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model1_security_analyst/train_model1_kaggle.py` (Line 427)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `kaggle/model1_security_analyst/train_model1_kaggle.py` (Line 428)
- **Description**: Accumulating string 'step_counter' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `kaggle/model1_security_analyst/train_model1_kaggle.py` (Line 449)
- **Description**: Accumulating string 'epoch_loss' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model1_security_analyst/test_model1_kaggle.py` (Line 275)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `kaggle/model1_security_analyst/test_model1_kaggle.py` (Line 276)
- **Description**: Accumulating string 'case_counter' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model1_security_analyst/test_model1_kaggle.py` (Line 325)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `kaggle/model1_security_analyst/test_model1_kaggle.py` (Line 326)
- **Description**: Accumulating string 'counter' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `kaggle/model1_security_analyst/test_model1_kaggle.py` (Line 656)
- **Description**: Accumulating string 'html_content' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `kaggle/model2_patch_generator/train_model2_kaggle.py` (Line 394)
- **Description**: Accumulating string 'prompt' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model2_patch_generator/public_benchmarking_model2.py` (Line 266)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic String Concatenation in Loop (PERF-102)
- **File**: `kaggle/model2_patch_generator/public_benchmarking_model2.py` (Line 389)
- **Description**: Accumulating string 'vals' with '+=' in a loop causes O(N^2) memory reallocation.
- **Remediation**: Use ''.join(...) instead.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model2_patch_generator/public_benchmarking_model2.py` (Line 503)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model2_patch_generator/test_model2_kaggle.py` (Line 74)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model2_patch_generator/benchmark_model2_kaggle.py` (Line 374)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

#### [MEDIUM] Quadratic O(N*M) Nested Loop Lookups (PERF-103)
- **File**: `kaggle/model2_patch_generator/benchmark_model2_kaggle.py` (Line 603)
- **Description**: Iterating through collections inside an outer loop scales as O(N*M).
- **Remediation**: Pre-index keys into a set() or dict for O(1) hash lookups.

---
*Powered by [VAJRA Security Auditor](https://github.com/apps/vajra-bot) - Autonomous AST & Cryptographic Review*