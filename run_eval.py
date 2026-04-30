#!/usr/bin/env python3
"""
run_eval.py
===========

IaC-Reviewer-Bench evaluation harness.

Loads the canonical dataset built by build_dataset.py and runs three frontier
reasoning-class models (OpenAI GPT-5.5, Anthropic Claude Sonnet 4.6, Google
Gemini 2.5 Pro) across the three benchmark tasks:

  T1 - Free-form Finding
  T2 - Scanner False-Positive Triage
  T3 - Compliance-Control Mapping (PCI DSS v4.0.1, NIST 800-53 Rev 5)

Outputs are written as JSONL files, one per (task, model) pair, suitable for
downstream metric computation in a separate analysis notebook.

Author : Avitesh Kesharwani, MS UNCC, IEEE Senior Member

Notes
-----
1. Provider SDKs are imported lazily so the script runs even if a single SDK
   is missing.
2. All three providers are called via their official Python SDKs where
   possible; Gemini is called via google-generativeai.
3. Token usage is recorded per call and a cost-per-call estimate is computed
   using a configurable price table so the cost-per-true-finding metric in
   the paper can be reproduced.
4. JSON output from models is requested via system prompt + parsing that
   tolerates stray prose around the JSON block.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

LOG = logging.getLogger("run_eval")
from dotenv import load_dotenv
load_dotenv()


# ---------------------------------------------------------------------------
# Pricing (USD per 1K tokens). Update as provider pricing evolves.
# ---------------------------------------------------------------------------

PRICE_USD_PER_1K = {
    "gpt-4o":           {"in": 0.0050, "out": 0.0150},
    "claude-sonnet-4.6":{"in": 0.0030, "out": 0.0150},
    "gemini-2.5-pro":   {"in": 0.00125, "out": 0.00500},
}

MODEL_REGISTRY: Dict[str, Dict[str, str]] = {
    "gpt-4o":             {"provider": "openai",    "name": "gpt-4o"},
    "claude-sonnet-4.6":  {"provider": "anthropic", "name": "claude-sonnet-4-6"},
    "gemini-2.5-pro":     {"provider": "google",    "name": "gemini-2.5-pro"},
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class CallResult:
    text: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    error: Optional[str] = None
    latency_sec: float = 0.0
    raw: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Code extraction
# ---------------------------------------------------------------------------

CODE_GLOBS_TF   = ("*.tf", "*.tfvars", "variables.tf", "outputs.tf")
CODE_GLOBS_HELM = ("Chart.yaml", "values.yaml", "values.yml", "templates/*.yaml",
                   "templates/*.yml", "templates/*.tpl")

MAX_FILES = 12
MAX_CHARS_PER_FILE = 7000
MAX_TOTAL_CHARS    = 28000


def extract_iac_snippet(module_path: str, iac_type: str) -> str:
    base = Path(module_path)
    globs = CODE_GLOBS_TF if iac_type == "terraform" else CODE_GLOBS_HELM
    files: List[Path] = []
    for g in globs:
        files.extend(base.glob(g))
    files = sorted(set(files))[:MAX_FILES]

    parts: List[str] = []
    total = 0
    for f in files:
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        if len(text) > MAX_CHARS_PER_FILE:
            text = text[:MAX_CHARS_PER_FILE] + "\n# ... (truncated)\n"
        chunk = f"# FILE: {f.relative_to(base) if base in f.parents or f.parent == base else f.name}\n{text}"
        if total + len(chunk) > MAX_TOTAL_CHARS:
            break
        parts.append(chunk)
        total += len(chunk)
    return "\n\n".join(parts) if parts else "# (no readable IaC files found)"


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

CANONICAL_TAXONOMY_HINT = """\
Use one of the following canonical misconfiguration classes when classifying:
encryption_at_rest_missing, encryption_in_transit_missing, public_object_storage,
permissive_security_group, public_compute_endpoint, iam_overly_permissive,
iam_root_or_admin_use, missing_logging_audit, missing_versioning_backup,
hardcoded_secrets, weak_kms_or_key_policy, missing_resource_limits,
missing_network_policy, permissive_rbac, privileged_container,
missing_pod_security, missing_image_scan_or_pin, missing_tls_for_ingress,
expensive_oversized_resource, data_transfer_anti_pattern.
"""

SYSTEM_PRELUDE = (
    "You are a senior cloud security and compliance architect at a regulated "
    "fintech organization. You review Terraform and Helm code for "
    "production-readiness, security, reliability, cost, and compliance "
    "issues. You answer with strictly valid JSON only, no prose around it."
)


def build_task1_prompt(record: Dict[str, Any]) -> str:
    snippet = extract_iac_snippet(record["meta"]["path"], record["meta"]["iac_type"])
    return (
        f"{SYSTEM_PRELUDE}\n\n"
        f"TASK 1 - Free-form finding.\n"
        f"Read the following {record['meta']['iac_type']} code and produce a JSON "
        f"object with key 'findings' whose value is a list. Each finding has "
        f"fields: category (security|reliability|cost|compliance), "
        f"misconfig_class, resource, file_path, severity (LOW|MEDIUM|HIGH|CRITICAL), "
        f"explanation, remediation.\n\n"
        f"{CANONICAL_TAXONOMY_HINT}\n"
        f"CODE:\n{snippet}\n"
    )


def build_task2_prompt(record: Dict[str, Any]) -> str:
    snippet = extract_iac_snippet(record["meta"]["path"], record["meta"]["iac_type"])
    alerts = []
    for f in record.get("raw_findings", []):
        alerts.append({
            "scanner":   f.get("scanner"),
            "rule_id":   f.get("rule_id"),
            "resource":  f.get("resource"),
            "file_path": f.get("file_path"),
            "message":   f.get("message"),
            "severity":  f.get("severity"),
        })
    alerts_json = json.dumps(alerts, indent=2)[:18000]
    return (
        f"{SYSTEM_PRELUDE}\n\n"
        f"TASK 2 - Scanner alert triage.\n"
        f"For each alert below, decide TRUE_POSITIVE, FALSE_POSITIVE, "
        f"DUPLICATE, or OUT_OF_SCOPE in the context of a PCI DSS in-scope, "
        f"internet-facing service. Return strictly JSON: an object with key "
        f"'decisions' holding a list of objects with fields: scanner, rule_id, "
        f"resource, decision, justification.\n\n"
        f"CODE:\n{snippet}\n\n"
        f"ALERTS:\n{alerts_json}\n"
    )


def build_task3_prompt(record: Dict[str, Any]) -> str:
    findings = record.get("canonical_findings", [])[:25]
    findings_json = json.dumps(findings, indent=2)[:18000]
    return (
        f"{SYSTEM_PRELUDE}\n\n"
        f"TASK 3 - Compliance control mapping.\n"
        f"For each finding below, output PCI DSS v4.0.1 requirement IDs and "
        f"NIST SP 800-53 Rev 5 control IDs that apply, with auditor-ready "
        f"rationale. Return strictly JSON: an object with key 'mappings' "
        f"holding a list of objects with fields: finding_id, "
        f"misconfig_class, pci_controls, nist_controls, rationale.\n\n"
        f"FINDINGS:\n{findings_json}\n"
    )


# ---------------------------------------------------------------------------
# JSON parsing tolerant of stray prose
# ---------------------------------------------------------------------------

JSON_BLOCK_RE = re.compile(r"\{[\s\S]*\}\s*$", re.MULTILINE)


def parse_json_safely(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except Exception:
            pass
    m = JSON_BLOCK_RE.search(text)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Provider clients (lazy)
# ---------------------------------------------------------------------------

def _price_for(model_key: str, in_tok: int, out_tok: int) -> float:
    pr = PRICE_USD_PER_1K.get(model_key, {"in": 0.0, "out": 0.0})
    return (in_tok / 1000.0) * pr["in"] + (out_tok / 1000.0) * pr["out"]


def call_openai(model_name: str, prompt: str, model_key: str) -> CallResult:
    from openai import OpenAI
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

    t0 = time.time()
    try:
        resp = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PRELUDE},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=2048,
        )

        latency = time.time() - t0

        text = resp.choices[0].message.content or ""

        usage = getattr(resp, "usage", None)
        in_tok = getattr(usage, "prompt_tokens", 0) or 0
        out_tok = getattr(usage, "completion_tokens", 0) or 0

        return CallResult(
            text=text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=_price_for(model_key, in_tok, out_tok),
            latency_sec=latency,
        )

    except Exception as exc:
        return CallResult(error=str(exc), latency_sec=time.time() - t0)


def call_anthropic(model_name: str, prompt: str, model_key: str) -> CallResult:
    import anthropic  # type: ignore
    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    t0 = time.time()
    try:
        resp = client.messages.create(
            model=model_name,
            max_tokens=4096,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )
        latency = time.time() - t0
        text_parts = []
        for blk in resp.content:
            if getattr(blk, "type", None) == "text":
                text_parts.append(blk.text)
        text = "\n".join(text_parts)
        usage = getattr(resp, "usage", None)
        in_tok  = getattr(usage, "input_tokens", 0) or 0
        out_tok = getattr(usage, "output_tokens", 0) or 0
        return CallResult(
            text=text, input_tokens=in_tok, output_tokens=out_tok,
            cost_usd=_price_for(model_key, in_tok, out_tok),
            latency_sec=latency,
        )
    except Exception as exc:
        return CallResult(error=str(exc), latency_sec=time.time() - t0)


def call_google(model_name: str, prompt: str, model_key: str) -> CallResult:
    from google import genai
    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

    t0 = time.time()
    try:
        resp = client.models.generate_content(
            model=model_name,
            contents=prompt,
        )

        latency = time.time() - t0

        text = ""
        if resp.text:
            text = resp.text

        usage = getattr(resp, "usage_metadata", None)
        in_tok = getattr(usage, "prompt_token_count", 0) or 0
        out_tok = getattr(usage, "candidates_token_count", 0) or 0

        return CallResult(
            text=text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=_price_for(model_key, in_tok, out_tok),
            latency_sec=latency,
        )

    except Exception as exc:
        return CallResult(error=str(exc), latency_sec=time.time() - t0)


def call_model(model_key: str, prompt: str) -> CallResult:
    cfg = MODEL_REGISTRY[model_key]
    provider = cfg["provider"]
    name = cfg["name"]
    if provider == "openai":
        return call_openai(name, prompt, model_key)
    if provider == "anthropic":
        return call_anthropic(name, prompt, model_key)
    if provider == "google":
        return call_google(name, prompt, model_key)
    return CallResult(error=f"unknown provider {provider}")


# ---------------------------------------------------------------------------
# Eval loop
# ---------------------------------------------------------------------------

TASK_BUILDERS = {
    "task1": build_task1_prompt,
    "task2": build_task2_prompt,
    "task3": build_task3_prompt,
}


def run_eval(
    dataset: List[Dict[str, Any]],
    model_keys: List[str],
    tasks: List[str],
    out_dir: Path,
    sleep_sec: float = 0.4,
    max_modules: Optional[int] = None,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for task in tasks:
        for mk in model_keys:
            out_path = out_dir / f"{task}_{mk}.jsonl"
            LOG.info("Running %s on %s -> %s", task, mk, out_path)
            with out_path.open("w") as f_out:
                for idx, record in enumerate(dataset, start=1):
                    if max_modules and idx > max_modules:
                        break
                    builder = TASK_BUILDERS[task]
                    prompt = builder(record)
                    result = call_model(mk, prompt)
                    parsed = parse_json_safely(result.text) if not result.error else None
                    payload = {
                        "task": task,
                        "model": mk,
                        "module_meta": record["meta"],
                        "prompt_len": len(prompt),
                        "input_tokens":  result.input_tokens,
                        "output_tokens": result.output_tokens,
                        "cost_usd":      round(result.cost_usd, 6),
                        "latency_sec":   round(result.latency_sec, 3),
                        "error":         result.error,
                        "raw_text":      result.text,
                        "parsed":        parsed,
                    }
                    f_out.write(json.dumps(payload) + "\n")
                    f_out.flush()
                    if idx % 20 == 0:
                        LOG.info("  ...%d records", idx)
                    if sleep_sec > 0:
                        time.sleep(sleep_sec)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def load_dataset(path: Path, shuffle: bool = True, seed: int = 42,
                 limit: Optional[int] = None) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                continue
    if shuffle:
        random.Random(seed).shuffle(records)
    if limit:
        records = records[:limit]
    return records


def main() -> int:
    p = argparse.ArgumentParser(description="Run IaC-Reviewer-Bench evaluation")
    p.add_argument("--dataset", type=Path, required=True,
                   help="Path to iac_reviewer_bench_dataset.jsonl")
    p.add_argument("--out", type=Path, required=True,
                   help="Output directory for per-(task,model) JSONL files")
    p.add_argument("--models", nargs="*", default=list(MODEL_REGISTRY.keys()),
                   choices=list(MODEL_REGISTRY.keys()))
    p.add_argument("--tasks",  nargs="*", default=["task1", "task2", "task3"],
                   choices=["task1", "task2", "task3"])
    p.add_argument("--limit",  type=int, default=None,
                   help="Optional cap on modules per task,model")
    p.add_argument("--sleep",  type=float, default=0.4)
    p.add_argument("--seed",   type=int,   default=42)
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    LOG.info("Loading dataset from %s", args.dataset)
    dataset = load_dataset(args.dataset, shuffle=True, seed=args.seed, limit=args.limit)
    LOG.info("Loaded %d records", len(dataset))

    run_eval(
        dataset=dataset,
        model_keys=args.models,
        tasks=args.tasks,
        out_dir=args.out,
        sleep_sec=args.sleep,
        max_modules=args.limit,
    )
    LOG.info("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
