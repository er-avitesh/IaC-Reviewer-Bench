# IaC-Reviewer-Bench

**Author:** Avitesh Kesharwani, MS UNCC, IEEE Senior Member
**Target platform:** Windows 10/11 (PowerShell), with notes for WSL/Linux.

This repository accompanies the paper *"IaC-Reviewer-Bench: Evaluating Frontier Large Language Models on Production-Readiness, Security, and Compliance Review of Terraform and Helm in Regulated Fintech Environments."*

---

## Benchmark Results (10-module pilot run)

| Metric | gpt-4o | claude-sonnet-4.6 | gemini-2.5-pro |
|---|---|---|---|
| T1 Macro F1 | 0.308 | 0.246 | 0.062 |
| T1 Resource F1 | 0.000 | 0.022 | 0.000 |
| T2 TP Recall | 1.000 | 1.000 | 1.000 |
| T2 FP Suppression | 0.449 | 0.623 | 0.448 |
| T3 PCI Strict | 0.333 | 0.000 | 0.000 |
| T3 NIST Strict | 0.333 | 0.000 | 0.000 |
| Cost / true finding (USD) | 0.023 | 0.056 | n/a |

Inter-model agreement: Fleiss κ = 0.501 (moderate). Cohen's κ: gpt-4o vs claude = 0.635, gpt-4o vs gemini = 0.399, claude vs gemini = 0.421.

Key findings:
- All models achieve perfect T2 TP Recall (1.000) but cannot distinguish DUPLICATE from TRUE_POSITIVE alerts — an inherent stateless limitation.
- T1 F1 is low due to precision collapse: models over-report (high recall, low precision), which is the safer failure mode in a security context.
- gpt-4o is the only model to achieve non-zero strict compliance mapping accuracy (T3 PCI/NIST Strict = 0.333).
- Claude leads on T2 FP suppression (0.623 vs ~0.449 for the others).
- Gemini produced zero T1 true positives on this pilot slice, making cost-per-true-finding undefined.

---

## Repository contents

| File | Purpose |
|---|---|
| `build_dataset.py` | Samples Terraform and Helm modules, runs Checkov, tfsec, Trivy, and KICS, normalizes findings into a unified 21-class taxonomy, deduplicates across scanners, attaches PCI DSS v4.0.1 and NIST 800-53 Rev 5 mappings, writes a JSONL dataset. |
| `run_eval.py` | Runs gpt-4o, claude-sonnet-4.6, and gemini-2.5-pro on three benchmark tasks and writes per-(task,model) JSONL outputs. |
| `compute_metrics.py` | Aggregates JSONL outputs into precision, recall, F1, FP-suppression, control-mapping accuracy, cost-per-true-finding, and inter-model agreement (Cohen's + Fleiss' kappa). |
| `check_connectivity.py` | Round-trip ping to all three providers; run before spending money. |
| `.env` (you create) | Stores your three API keys. **Never commit this file.** |
| `.gitignore` | Excludes `.env`, scanner output, Python caches. |

---

## Dataset schema

Each line of `iac_reviewer_bench_dataset.jsonl` is a JSON object:

```json
{
  "meta": {
    "fingerprint": "abc123",
    "source": "aws_samples",
    "repo_name": "terraform-aws-s3-bucket",
    "path": "/data/.../examples/complete",
    "iac_type": "terraform",
    "module_id": null
  },
  "raw_findings": [...],
  "canonical_findings": [...],
  "stats": {
    "n_raw": 36,
    "n_canonical": 6,
    "by_class": { "encryption_at_rest_missing": 1, "public_object_storage": 1, ... }
  }
}
```

Each finding (raw or canonical) has:

| Field | Description |
|---|---|
| `scanner` | `checkov`, `tfsec`, `trivy`, or `kics` |
| `rule_id` | Scanner-native rule ID (e.g. `CKV_AWS_20`, `AVD-AWS-0092`) |
| `severity` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `resource` | Terraform resource name (e.g. `aws_s3_bucket`) |
| `file_path` | Path to the `.tf` file within the module |
| `message` | Human-readable description |
| `canonical_class` | One of the 21 canonical misconfiguration classes (see below) |
| `pci_controls` | PCI DSS v4.0.1 requirement IDs |
| `nist_controls` | NIST 800-53 Rev 5 control IDs |
| `merged_scanners` | List of scanners that detected the same logical issue (canonical findings only) |

### Canonical misconfiguration taxonomy (21 classes)

`encryption_at_rest_missing`, `encryption_in_transit_missing`, `public_object_storage`, `permissive_security_group`, `public_compute_endpoint`, `iam_overly_permissive`, `iam_root_or_admin_use`, `missing_logging_audit`, `missing_versioning_backup`, `hardcoded_secrets`, `weak_kms_or_key_policy`, `missing_resource_limits`, `missing_network_policy`, `permissive_rbac`, `privileged_container`, `missing_pod_security`, `missing_image_scan_or_pin`, `missing_tls_for_ingress`, `expensive_oversized_resource`, `data_transfer_anti_pattern`, `low_signal_misc`

### Deduplication approach

Canonical findings are deduplicated across scanners by `(canonical_class)` only. One entry per class per module, with `merged_scanners` listing every scanner that detected it. This produces a sparse, class-level oracle intentionally — the low T1 F1 scores reflect model over-reporting, not scoring leniency.

---

## Lessons learned (read first if you hit issues)

1. **Microsoft Store Python is a trap.** The Windows alias routes to the Store, which sandboxes pip and breaks Checkov. Always install from python.org. If `python --version` opens the Store, disable the alias under Settings → Apps → Advanced app settings → App execution aliases.
2. **`brew` does not exist on Windows.** Use direct GitHub binary downloads.
3. **Trivy's Windows zip filename is versioned.** The pattern is `trivy_<version>_windows-64bit.zip`. The `releases/latest/download/` redirect does not work for the Windows asset; use a versioned URL.
4. **`Invoke-WebRequest` does not create parent directories.** Always `New-Item -ItemType Directory -Force` first.
5. **PATH only refreshes in new PowerShell sessions.** Close and reopen after any PATH change.
6. **`tfsec` is deprecated upstream.** Aqua merged it into Trivy. tfsec v1.28.x still works; it is kept here for cross-comparison with prior literature.
7. **VS Code caches its Python interpreter independently.** After `pip install`, run Python: Select Interpreter in the command palette and pick the python.org install, then Developer: Reload Window.
8. **The old Google SDK is dead.** `google.generativeai` is deprecated; use `google-genai`.
9. **Corporate TLS inspection (Zscaler, Netskope) breaks Python SSL.** Fix: `truststore.inject_into_ssl()` before any imports.
10. **Some corporate networks block generative-AI domains entirely.** If you see HTML with "Zscaler" or "Forbidden" in error responses, run the LLM evaluation on a personal machine.

---

## Step 1: Install Python 3.12

Python 3.12 is recommended over 3.13 — Checkov and several dependencies are better-tested against it.

1. Download the **Windows installer (64-bit)** from https://www.python.org/downloads/windows/
2. Run the installer. **Check "Add python.exe to PATH"** on the first screen.
3. After install, click "Disable path length limit" if prompted.

Open a fresh PowerShell and verify:

```powershell
python --version
pip --version
```

---

## Step 2: Install IaC scanners (Trivy, tfsec, Checkov)

```powershell
# Create tools folder
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\bin" | Out-Null

# Trivy v0.70.0
$trivyVersion = "0.70.0"
$zip = "$env:USERPROFILE\bin\trivy.zip"
Invoke-WebRequest `
    -Uri "https://github.com/aquasecurity/trivy/releases/download/v$trivyVersion/trivy_${trivyVersion}_windows-64bit.zip" `
    -OutFile $zip
Expand-Archive -Path $zip -DestinationPath "$env:USERPROFILE\bin" -Force
Remove-Item $zip
Remove-Item "$env:USERPROFILE\bin\LICENSE","$env:USERPROFILE\bin\README.md" -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\bin\contrib" -Recurse -ErrorAction SilentlyContinue

# tfsec (latest)
Invoke-WebRequest `
    -Uri "https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-windows-amd64.exe" `
    -OutFile "$env:USERPROFILE\bin\tfsec.exe"

# Add to PATH (current session + permanent)
$env:Path += ";$env:USERPROFILE\bin"
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:USERPROFILE\bin",
    "User"
)
```

**Close and reopen PowerShell**, then verify:

```powershell
trivy --version    # → Version: 0.70.0
tfsec --version    # → v1.28.x (deprecation banner is expected)
```

Install Checkov:

```powershell
pip install checkov
checkov --version  # → 3.x.x
```

---

## Step 3: Install Python dependencies

```powershell
pip install openai anthropic google-genai python-dotenv truststore
```

If you previously installed the old Google SDK:

```powershell
pip uninstall google-generativeai -y
```

---

## Step 4: Get API keys

| Provider | Dashboard | `.env` variable |
|---|---|---|
| OpenAI | https://platform.openai.com/api-keys | `OPENAI_API_KEY` |
| Anthropic | https://console.anthropic.com/settings/keys | `ANTHROPIC_API_KEY` |
| Google | https://aistudio.google.com/app/apikey | `GEMINI_API_KEY` |

Keys are shown only once at creation — copy immediately.

---

## Step 5: Create `.env`

In the project root (same folder as `run_eval.py`):

```
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=AIza...
```

Verify `.env` is in `.gitignore`:

```powershell
Get-Content .gitignore
```

If missing, add it:

```powershell
"`n.env" | Add-Content .gitignore
```

---

## Step 6: Connectivity check

```powershell
python check_connectivity.py
```

Expected:

```
Connectivity check results
==========================
  [OK  ] OpenAI     - reply='OK' latency=0.42s
  [OK  ] Anthropic  - reply='OK' latency=0.51s
  [OK  ] Google     - reply='OK' latency=0.38s
```

| Error | Cause | Fix |
|---|---|---|
| `CERTIFICATE_VERIFY_FAILED` | Corporate TLS inspection | Add `import truststore; truststore.inject_into_ssl()` at top of script |
| `403` with "Zscaler" HTML | Corporate domain block | Run on personal machine |
| `401` / Invalid API Key | Wrong key | Regenerate, paste into `.env`, retry |
| `429` / RateLimit | No billing | Add payment method at provider dashboard |

---

## Step 7: Smoke test the dataset build (zero LLM cost)

```powershell
$smoke = "$PWD\smoke_test"
New-Item -ItemType Directory -Force -Path "$smoke\aws-samples\bad-s3" | Out-Null
New-Item -ItemType Directory -Force -Path "$smoke\helm-charts" | Out-Null

@'
resource "aws_s3_bucket" "bad" {
  bucket = "my-bad-bucket-example"
  acl    = "public-read"
}

resource "aws_security_group" "wide_open" {
  name = "wide-open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'@ | Out-File -Encoding utf8 "$smoke\aws-samples\bad-s3\main.tf"

python build_dataset.py `
    --base   "$smoke" `
    --out    "$smoke\output" `
    --total  10 `
    --terra-quota 0 `
    --aws-quota 10 `
    --helm-quota 0 `
    --max-modules 5 `
    --log-level INFO

Get-Content "$smoke\output\dataset_summary.json"
```

Expected: `n_modules >= 1`, `total_raw_findings > 0`, `total_canonical_findings` noticeably smaller than raw (dedup is working). If raw findings are 0, re-check `trivy --version`, `tfsec --version`, `checkov --version`.

---

## Step 8: Smoke test the LLM harness (one module, ~$0.05)

```powershell
python run_eval.py `
    --dataset "$smoke\output\iac_reviewer_bench_dataset.jsonl" `
    --out     "$smoke\output\model_runs" `
    --models  gpt-4o claude-sonnet-4.6 gemini-2.5-pro `
    --tasks   task1 `
    --limit   1 `
    --sleep   0.4
```

Each output JSONL line should have non-zero `input_tokens`, `output_tokens`, a `cost_usd` value, and a `parsed.findings` list. Fix any `"error": ...` before scaling up.

---

## Step 9: Build the real dataset

Expected data layout under `$IAC_BENCH_BASE`:

```
$IAC_BENCH_BASE/
  terra_ds/
    terra_ds.sqlite        # TerraDS metadata DB
    repos/                 # extracted repo trees
  aws-samples/             # cloned AWS Samples Terraform repos
  helm-charts/             # Helm chart sources
```

```powershell
$env:IAC_BENCH_BASE = "C:\Projects\iac-reviewer-bench-data"

python build_dataset.py `
    --base "$env:IAC_BENCH_BASE" `
    --out  "$env:IAC_BENCH_BASE\output" `
    --total 1500 `
    --terra-quota 1000 `
    --aws-quota 250 `
    --helm-quota 250 `
    --seed 42
```

Outputs:
- `output/iac_reviewer_bench_dataset.jsonl` — the canonical dataset
- `output/dataset_summary.json` — counts and source distribution

---

## Step 10: Run the LLM evaluation

```powershell
python run_eval.py `
    --dataset "$env:IAC_BENCH_BASE\output\iac_reviewer_bench_dataset.jsonl" `
    --out     "$env:IAC_BENCH_BASE\output\model_runs" `
    --models  gpt-4o claude-sonnet-4.6 gemini-2.5-pro `
    --tasks   task1 task2 task3 `
    --sleep   0.4
```

Produces nine JSONL files: `task{1,2,3}_{model}.jsonl`.

**Cost guidance.** Run `--limit 50` first and multiply the aggregate `cost_usd` by 30 to project full cost. Expected total across all three providers and all three tasks: roughly USD 200–400 depending on module sizes.

---

## Step 11: Compute metrics

```powershell
python compute_metrics.py `
    --dataset     "$env:IAC_BENCH_BASE\output\iac_reviewer_bench_dataset.jsonl" `
    --results-dir "$env:IAC_BENCH_BASE\output\model_runs" `
    --out         "$env:IAC_BENCH_BASE\output\metrics" `
    --models      gpt-4o claude-sonnet-4.6 gemini-2.5-pro
```

Outputs:
- `metrics/metrics_report.json` — full report with per-class breakdown and inter-model kappa
- `metrics/metrics_table.md` — paper-ready Table III

---

## Quick-start from zero (personal Windows machine)

1. Install Python 3.12 from python.org (check "Add to PATH").
2. Install Git from https://git-scm.com/download/win.
3. Clone this repo and open a PowerShell in the project folder.
4. Run the Step 2 block (Trivy + tfsec + PATH).
5. **Close and reopen PowerShell.**
6. `pip install checkov openai anthropic google-genai python-dotenv truststore`
7. Create `.env` with your three API keys (Step 5).
8. `python check_connectivity.py` — confirm three OKs.
9. Run smoke tests (Steps 7 and 8).
10. Scale up (Steps 9, 10, 11).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `python --version` opens Microsoft Store | App execution alias | Disable in Settings → Apps → App execution aliases |
| `Invoke-WebRequest` "could not find part of path" | Missing parent dir | `New-Item -ItemType Directory -Force` first |
| `trivy --version` "not recognized" | PATH not refreshed | Open fresh PowerShell |
| Pylance: "Import X could not be resolved" | Wrong interpreter in VS Code | Ctrl+Shift+P → Python: Select Interpreter → pick python.org install |
| `CERTIFICATE_VERIFY_FAILED` | Corporate TLS inspection | `import truststore; truststore.inject_into_ssl()` at top of script |
| `403` with HTML body mentioning "Zscaler" | Corporate URL block | Run on personal machine |
| `0x80070005` during Python install | Policy blocks per-machine path | Use "Customize installation" with per-user path |
| gRPC errors with cert mentions | Old `google.generativeai` SDK | Switch to `google-genai` (HTTPS, not gRPC) |
| `total_raw_findings: 0` in dataset summary | Scanner not on PATH | Verify `trivy`, `tfsec`, `checkov` all print version numbers in same shell |
| `HTTP 400 Bad Request` from OpenAI | Invalid model name | Use `gpt-4o` (not `gpt-5.5` or other non-existent names) |

---

## Reproducibility

Reference environment for the pilot results reported above:

| Component | Version |
|---|---|
| OS | Windows 11 24H2, build 26100+ |
| Python | 3.12.x (python.org) |
| Trivy | v0.70.0 |
| tfsec | v1.28.14 |
| Checkov | 3.2.x |
| OpenAI SDK | v1.x (latest stable) |
| Anthropic SDK | latest stable |
| Google SDK | `google-genai` |
| Models | `gpt-4o`, `claude-sonnet-4-6`, `gemini-2.5-pro` |
| Dataset seed | 42 |
| Dedup strategy | class-only (`canonical_class`), one finding per class per module |
| Scoring VALID_CLASSES | 10-class subset (see `compute_metrics.py:VALID_CLASSES`) |
