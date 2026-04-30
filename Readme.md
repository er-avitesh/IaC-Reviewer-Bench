# IaC-Reviewer-Bench: End-to-End Setup and Run Guide

**Author:** Avitesh Kesharwani, MS UNCC, IEEE Senior Member
**Target platform:** Windows 10/11 (PowerShell), with notes for WSL/Linux.

This bundle accompanies the paper *"IaC-Reviewer-Bench: Evaluating Frontier
Large Language Models on Production-Readiness, Security, and Compliance
Review of Terraform and Helm in Regulated Fintech Environments."*

---

## What's in this repo

| File | Purpose |
| --- | --- |
| `IaC-Reviewer-Bench-Kesharwani.docx` | The IEEE-style paper (~11 pages). |
| `build_dataset.py` | Samples Terraform and Helm modules, runs Checkov, tfsec, Trivy on each, normalizes findings into a unified taxonomy, attaches PCI DSS and NIST 800-53 mappings, writes a JSONL dataset. |
| `run_eval.py` | Runs the three frontier LLMs (GPT-5.5, Claude Sonnet 4.6, Gemini 2.5 Pro) on the three benchmark tasks and writes per-(task,model) JSONL outputs. |
| `compute_metrics.py` | Aggregates the JSONL outputs into precision, recall, F1, FP-suppression, control-mapping accuracy, cost-per-true-finding, and inter-model agreement. |
| `check_connectivity.py` | Tiny round-trip ping to all three providers; run this before spending money. |
| `.env` (you create) | Stores your three API keys. **Never commit this file.** |
| `.gitignore` | Excludes `.env`, scanner output, Python caches. |

---

## Lessons learned from the work-laptop install (read first if you hit issues)

These are the exact failure modes we already debugged. Knowing them saves an hour.

1. **Microsoft Store Python is a trap.** The Windows app-execution-alias for `python.exe` routes to the Store, which sandboxes pip and breaks Checkov. **Always install Python from python.org.** If you ever see "File association not found for extension .py" or `0x80070005`, disable the alias under Settings -> Apps -> Advanced app settings -> App execution aliases.
2. **`brew` does not exist on Windows.** Older docs mention it; ignore them. Use direct GitHub binary downloads.
3. **Trivy's Windows zip filename uses lowercase and an explicit version number.** The pattern is `trivy_<version>_windows-64bit.zip`. The `releases/latest/download/` redirect does not work for Trivy's Windows asset; you must use a versioned URL.
4. **`Invoke-WebRequest` does not create parent directories.** Always run `New-Item -ItemType Directory -Force` first.
5. **PATH only refreshes in *new* PowerShell sessions.** After modifying environment variables, close the window and open a fresh one.
6. **`tfsec` is deprecated upstream.** Aqua merged it into Trivy. tfsec v1.28.x still works and we keep it for backward comparison with prior literature; Trivy is the actively maintained successor.
7. **VS Code's Python extension caches its interpreter independently.** If `pip install xyz` works in PowerShell but VS Code says "Import xyz could not be resolved", run **Python: Select Interpreter** in the command palette and pick the python.org install, then **Developer: Reload Window**.
8. **The old Google SDK is dead.** `google.generativeai` is deprecated; we use `google-genai` (different import path and API).
9. **Corporate networks with TLS inspection (Zscaler, Netskope, etc.) break Python SSL.** The fix on Windows is `truststore.inject_into_ssl()`, which delegates trust to the OS certificate store.
10. **Some corporate networks block generative-AI domains entirely.** If you see HTML in your error response with words like "Zscaler" or "Forbidden", you are blocked at the policy layer and no code change can fix it. Run the LLM evaluation on a personal machine instead.

---

## Step 1: Install Python 3.12

Python 3.12 is recommended over 3.13 because Checkov and a few other dependencies have been better-tested against it.

1. Open https://www.python.org/downloads/windows/ in your browser.
2. Click "Latest Python 3 Release - Python 3.12.x" (newest 3.12.x build).
3. Scroll to "Files" and download **"Windows installer (64-bit)"**.
4. Run the installer.
5. **Critical:** check the box **"Add python.exe to PATH"** at the bottom of the first installer screen.
6. Click "Install Now".
7. After install, click "Disable path length limit" if prompted.

Close all PowerShell windows, then open a fresh one. Verify:

```powershell
python --version
pip --version
```

Both should print version numbers. If `python --version` opens the Microsoft Store, see Lesson 1 above.

---

## Step 2: Install IaC scanners (Trivy, tfsec, Checkov)

Run this whole block in PowerShell. It creates a tools folder, downloads Trivy and tfsec as standalone binaries, and adds them to PATH permanently.

```powershell
# Create tools folder
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\bin" | Out-Null

# Trivy v0.70.0 (update version if newer release is out; check https://github.com/aquasecurity/trivy/releases)
$trivyVersion = "0.70.0"
$zip = "$env:USERPROFILE\bin\trivy.zip"
Invoke-WebRequest `
    -Uri "https://github.com/aquasecurity/trivy/releases/download/v$trivyVersion/trivy_${trivyVersion}_windows-64bit.zip" `
    -OutFile $zip
Expand-Archive -Path $zip -DestinationPath "$env:USERPROFILE\bin" -Force
Remove-Item $zip
# Optional cleanup of bundled docs
Remove-Item "$env:USERPROFILE\bin\LICENSE","$env:USERPROFILE\bin\README.md" -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\bin\contrib" -Recurse -ErrorAction SilentlyContinue

# tfsec (latest)
Invoke-WebRequest `
    -Uri "https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-windows-amd64.exe" `
    -OutFile "$env:USERPROFILE\bin\tfsec.exe"

# Add to PATH for this session
$env:Path += ";$env:USERPROFILE\bin"

# Add to PATH permanently (user-level, no admin needed)
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:USERPROFILE\bin",
    "User"
)
```

**Close PowerShell, open a fresh window**, and verify:

```powershell
trivy --version
tfsec --version
```

Trivy should print `Version: 0.70.0`. tfsec will print a banner about being deprecated and then `v1.28.x` or similar. That banner is expected.

Now install Checkov via pip:

```powershell
pip install checkov
checkov --version
```

Checkov will take a couple of minutes (it pulls in many provider plugins). When done, it prints `3.x.x`.

---

## Step 3: Install Python dependencies

```powershell
pip install openai anthropic google-genai python-dotenv truststore
```

Notes:

- `openai` is the modern v1.x SDK (do not use the legacy `openai.ChatCompletion` style).
- `anthropic` is Anthropic's official Python SDK.
- `google-genai` is the **new** Google SDK (replaces the deprecated `google.generativeai` package).
- `python-dotenv` lets us read API keys from a `.env` file at the project root.
- `truststore` makes Python use the OS certificate store, which is required behind any TLS-inspecting corporate network.

If you previously installed the old Google SDK, remove it:

```powershell
pip uninstall google-generativeai -y
```

---

## Step 4: Get API keys

You need three keys. Each provider requires a billing setup before keys actually work.

| Provider | Where to get | Variable name |
| --- | --- | --- |
| OpenAI | https://platform.openai.com/api-keys | `OPENAI_API_KEY` |
| Anthropic | https://console.anthropic.com/settings/keys | `ANTHROPIC_API_KEY` |
| Google | https://aistudio.google.com/app/apikey | `GEMINI_API_KEY` |

When OpenAI and Anthropic show you a new key, **copy it immediately**; they only display it once.

---

## Step 5: Create `.env` (this is your single source of truth for keys)

In the project root (the same folder as `run_eval.py`), create a file named `.env` containing:

```
OPENAI_API_KEY=sk-...your-openai-key...
ANTHROPIC_API_KEY=sk-ant-...your-anthropic-key...
GEMINI_API_KEY=AIza...your-google-key...
```

**Never commit this file.** Confirm `.env` is in `.gitignore`:

```powershell
Get-Content .gitignore
```

If `.env` is missing from `.gitignore`, add it:

```powershell
"`n.env" | Add-Content .gitignore
```

The Python scripts load this file automatically via `python-dotenv` (the `load_dotenv()` call near the top of each script).

If you ever accidentally commit `.env` or paste a key into a script, regenerate that key at the provider's dashboard immediately. GitHub crawlers find leaked keys within minutes.

---

## Step 6: Connectivity check (do this before any real run)

This costs less than a cent across all three providers and proves your keys, billing, and network all work.

```powershell
python check_connectivity.py
```

Expected output:

```
Connectivity check results
==========================
  [OK  ] OpenAI     - reply='OK' latency=0.42s
  [OK  ] Anthropic  - reply='OK' latency=0.51s
  [OK  ] Google     - reply='OK' latency=0.38s
```

If any line says FAIL:

- **`CERTIFICATE_VERIFY_FAILED`**: corporate TLS inspection. Make sure `truststore.inject_into_ssl()` is at the top of `check_connectivity.py` (before any other imports). On a personal network this should not occur.
- **`403 Forbidden` with HTML body containing "Zscaler" or similar**: corporate policy block. Run from a personal machine.
- **`401` or `Invalid API Key`**: regenerate the key, paste into `.env`, save, retry.
- **`429` or `RateLimit`**: billing not configured. Visit the provider dashboard and add a payment method.
- **`Connection error`**: usually transient network. Try again in a minute, or check whether you are behind a VPN.

---

## Step 7: Smoke test the data build (zero LLM cost)

Before scanning thousands of real modules, confirm the pipeline works end-to-end on a tiny set of intentionally bad Terraform files. This costs nothing because no LLM is called.

```powershell
# Create a smoke-test layout with deliberately bad Terraform
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

# Run build_dataset.py against the smoke folder, AWS-Samples-only, capped at 5 modules
python build_dataset.py `
    --base   "$smoke" `
    --out    "$smoke\output" `
    --total  10 `
    --terra-quota 0 `
    --aws-quota 10 `
    --helm-quota 0 `
    --max-modules 5 `
    --log-level INFO

# Inspect the output
Get-Content "$smoke\output\dataset_summary.json"
Get-Content "$smoke\output\iac_reviewer_bench_dataset.jsonl" | Select-Object -First 1
```

What you should see:

- The console prints one or two `[i/N] Scanning ...` lines.
- `dataset_summary.json` shows `n_modules >= 1` and `total_raw_findings > 0`.
- The first JSONL line contains real `raw_findings` and `canonical_findings` arrays with non-empty `canonical_class` fields.

If `total_raw_findings` is 0, one of the scanners is not actually being invoked. Re-check `trivy --version`, `tfsec --version`, `checkov --version` from the same shell.

---

## Step 8: Smoke test the LLM harness (one module, all three models)

Now that the dataset format is good, run a tiny LLM round-trip to confirm prompts and parsers work.

```powershell
python run_eval.py `
    --dataset "$smoke\output\iac_reviewer_bench_dataset.jsonl" `
    --out     "$smoke\output\model_runs" `
    --models  gpt-5.5 claude-sonnet-4.6 gemini-2.5-pro `
    --tasks   task1 `
    --limit   1 `
    --sleep   0.4
```

Inspect:

```powershell
Get-ChildItem "$smoke\output\model_runs"
Get-Content "$smoke\output\model_runs\task1_gpt-5.5.jsonl"
```

Each JSONL line should include non-zero `input_tokens`, non-zero `output_tokens`, a `cost_usd` value, and a `parsed` field containing a `findings` list. Total spend for this smoke test is under five cents.

If any model returns `"error": ...`, fix that one before scaling up.

---

## Step 9: Build the real 1,500-module dataset

Lay out the data sources first:

```
$IAC_BENCH_BASE/
  terra_ds/
    terra_ds.sqlite        # TerraDS metadata
    repos/                 # extracted repo trees
  aws-samples/             # cloned aws-samples Terraform repos
  helm-charts/             # mirrored Helm chart sources
```

Set the base location:

```powershell
$env:IAC_BENCH_BASE = "C:\Projects\iac-reviewer-bench-data"
```

Download / clone the source corpora into that layout (TerraDS dump, AWS Samples Terraform repos, Helm chart sources from Artifact Hub mirrors). This is the slowest one-time step; budget an evening.

Then run the full build:

```powershell
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

- `output/iac_reviewer_bench_dataset.jsonl` (the canonical dataset)
- `output/dataset_summary.json` (counts and source distribution)

---

## Step 10: Run the full LLM evaluation

```powershell
python run_eval.py `
    --dataset "$env:IAC_BENCH_BASE\output\iac_reviewer_bench_dataset.jsonl" `
    --out     "$env:IAC_BENCH_BASE\output\model_runs" `
    --models  gpt-5.5 claude-sonnet-4.6 gemini-2.5-pro `
    --tasks   task1 task2 task3 `
    --sleep   0.4
```

This produces nine JSONL files: `task{1,2,3}_{model}.jsonl`.

**Cost guidance.** Before launching the full 1,500-module run, do a 50-module dry run with `--limit 50` and inspect aggregate `cost_usd`. Multiply by 30 to project the full cost. Expected total across all three providers and all three tasks at the time of writing is roughly USD 200 to 400 depending on prompt and response sizes.

---

## Step 11: Compute metrics

```powershell
python compute_metrics.py `
    --dataset     "$env:IAC_BENCH_BASE\output\iac_reviewer_bench_dataset.jsonl" `
    --results-dir "$env:IAC_BENCH_BASE\output\model_runs" `
    --out         "$env:IAC_BENCH_BASE\output\metrics"
```

Outputs:

- `metrics/metrics_report.json`: full report including Cohen's and Fleiss' kappa.
- `metrics/metrics_table.md`: drop-in replacement for Table III in the paper.

Send these two files back and the paper's Section VII placeholders will be replaced with real numbers and the discussion section tightened to reflect actual findings.

---

## Quick reference: full personal-laptop bootstrap from zero

If you are setting up a brand-new personal Windows machine, here is the minimal sequence in order:

1. Install Python 3.12 from python.org (with PATH checkbox).
2. Install Git from https://git-scm.com/download/win.
3. Install VS Code from https://code.visualstudio.com.
4. Clone the repo: `git clone https://github.com/<you>/iac-reviewer-bench.git`.
5. Open a PowerShell in the project folder.
6. Run the Step 2 block (Trivy + tfsec + PATH).
7. **Close and reopen PowerShell.**
8. `pip install checkov openai anthropic google-genai python-dotenv truststore`.
9. Create `.env` with your three keys (Step 5).
10. `python check_connectivity.py` and confirm three OKs.
11. Run smoke tests (Steps 7 and 8).
12. Scale up (Steps 9, 10, 11).

---

## Troubleshooting cheat sheet

| Symptom | Cause | Fix |
| --- | --- | --- |
| `python --version` opens Microsoft Store | App execution alias intercepting | Disable in Settings -> Apps -> App execution aliases, install python.org Python |
| `Invoke-WebRequest` "could not find part of path" | Parent directory missing | `New-Item -ItemType Directory -Force` first |
| `Expand-Archive` succeeds, exe not found | PATH not refreshed | Close and reopen PowerShell |
| `trivy --version` "not recognized" | PATH update in this session only | Open fresh PowerShell, or `$env:Path += ";$env:USERPROFILE\bin"` |
| Pylance: "Import X could not be resolved" | VS Code points at different interpreter | Ctrl+Shift+P, Python: Select Interpreter, pick python.org install |
| `CERTIFICATE_VERIFY_FAILED` | Corporate TLS inspection | Add `import truststore; truststore.inject_into_ssl()` at top of script |
| `403 Forbidden` with HTML body, "Zscaler" mentioned | Corporate URL category block | Run on personal machine, or submit URL access request |
| `0x80070005` during installer | Per-machine install path blocked by policy | Use "Customize installation" with per-user path |
| gRPC errors with cert mentions | Old `google.generativeai` SDK plus corporate network | Switch to `google-genai`, which uses HTTPS instead of gRPC |
| Checkov "File association not found .py" warning | Cosmetic Store-alias warning, not a real error | Disable the alias as in row 1, or ignore |

---

## Notes on reproducibility for the paper

When this benchmark is published, reviewers will ask exactly which environment was used. The reference environment is:

- OS: Windows 11 24H2, build 26100 or later
- Python: 3.12.x from python.org (NOT Microsoft Store)
- Trivy: v0.70.0
- tfsec: v1.28.14 (deprecated; included for cross-comparison with prior literature)
- Checkov: 3.2.x
- OpenAI SDK: latest stable v1.x
- Anthropic SDK: latest stable
- Google SDK: `google-genai` (the maintained successor to the now-retired `google.generativeai`)
- Models: `gpt-5.5`, `claude-sonnet-4-6`, `gemini-2.5-pro`

Pin these versions in your final paper's "Reproducibility" appendix so future readers can reproduce numbers exactly.

---

## When you have results

Send back `metrics_report.json` and `metrics_table.md` and the paper's Section VII placeholders will be replaced with measured F1, FP-suppression rate, mapping accuracy, and cost-per-true-finding numbers, the abstract will be tightened to mention concrete results, and the discussion section will be rewritten around the empirical findings.