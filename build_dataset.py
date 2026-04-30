#!/usr/bin/env python3
"""
build_dataset.py
================

IaC-Reviewer-Bench dataset construction pipeline.

This script samples Terraform modules from TerraDS, AWS Samples, and Helm
charts from a local mirror of Artifact Hub, runs Checkov, tfsec, Trivy, and
KICS over each module, normalizes findings into a unified misconfiguration
schema, deduplicates across scanners, and attaches PCI DSS v4.0.1 and
NIST 800-53 Rev 5 control mappings.

Author : Avitesh Kesharwani, MS UNCC, IEEE Senior Member
License: MIT for the script; component scanners retain their own licenses.

Notable fixes versus the earlier sketch
---------------------------------------
1.  Checkov returns a dict (not always a list) when --output json is used.
    The shape is normalized here.
2.  tfsec v1.x emits {"results":[...]} on stdout with --format json; older
    versions emit a top-level list. Both shapes are handled.
3.  Trivy config emits {"Results":[...]} where each result has a
    "Misconfigurations" array; we flatten it.
4.  KICS writes its JSON report to a directory, not stdout. We read
    results.json from the requested output directory and clean up after.
5.  Robust subprocess timeouts and per-module isolation so a single bad
    module cannot abort the run.
6.  Deterministic stratified sampling driven by a fixed seed.
7.  Unified misconfiguration schema includes a stable canonical_class field
    used downstream for compliance attribution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_BASE = Path(os.environ.get("IAC_BENCH_BASE", "/data/iac-reviewer-bench"))
DEFAULT_SEED = 42

# Soft caps so a single scan cannot stall the pipeline.
SCAN_TIMEOUT_SEC = 300

LOG = logging.getLogger("build_dataset")


# ---------------------------------------------------------------------------
# Canonical misconfiguration taxonomy
#
# The taxonomy is intentionally compact (around 20 classes) and is the unit at
# which both metrics and PCI / NIST mappings are computed. Scanner rules are
# mapped to these classes via map_rule_to_canonical().
# ---------------------------------------------------------------------------

CANONICAL_CLASSES = [
    "encryption_at_rest_missing",
    "encryption_in_transit_missing",
    "public_object_storage",
    "permissive_security_group",
    "public_compute_endpoint",
    "iam_overly_permissive",
    "iam_root_or_admin_use",
    "missing_logging_audit",
    "missing_versioning_backup",
    "hardcoded_secrets",
    "weak_kms_or_key_policy",
    "missing_resource_limits",
    "missing_network_policy",
    "permissive_rbac",
    "privileged_container",
    "missing_pod_security",
    "missing_image_scan_or_pin",
    "missing_tls_for_ingress",
    "expensive_oversized_resource",
    "data_transfer_anti_pattern",
    "low_signal_misc",
]



# Heuristic mapping table. Real builds should hand-curate a richer mapping;
# this table is enough to bootstrap and is referenced in the paper as the
# canonical ontology.
RULE_PREFIX_TO_CLASS = [
    # Networking FIRST (higher priority)
    ("0.0.0.0/0", "permissive_security_group"),
    ("security group", "permissive_security_group"),
    ("ssh", "permissive_security_group"),
    ("rdp", "permissive_security_group"),

    # Storage (specific terms only)
    ("s3", "public_object_storage"),
    ("bucket", "public_object_storage"),
    ("public acl", "public_object_storage"),
    ("public access block", "public_object_storage"),

    # Encryption
    ("encryption", "encryption_at_rest_missing"),
    ("kms", "weak_kms_or_key_policy"),

    # Logging
    ("logging", "missing_logging_audit"),

    # Versioning
    ("versioning", "missing_versioning_backup"),
]

RULE_ID_MAP = {
    # --- Security group ---
    "AVD-AWS-0107": "permissive_security_group",
    "AWS-0107": "permissive_security_group",

    # --- S3 public exposure ---
    "AVD-AWS-0092": "public_object_storage",
    "AWS-0092": "public_object_storage",
    "AVD-AWS-0093": "public_object_storage",
    "AWS-0093": "public_object_storage",
    "AVD-AWS-0094": "public_object_storage",
    "AWS-0094": "public_object_storage",

    # --- Encryption ---
    "AVD-AWS-0088": "encryption_at_rest_missing",
    "AWS-0132": "encryption_at_rest_missing",
    "AVD-AWS-0132": "encryption_at_rest_missing",

    # --- Logging ---
    "AVD-AWS-0089": "missing_logging_audit",
    "AWS-0089": "missing_logging_audit",

    # --- Versioning ---
    "AVD-AWS-0090": "missing_versioning_backup",
    "AWS-0090": "missing_versioning_backup",
}

# Canonical class to (PCI DSS, NIST 800-53) seed mappings. These are
# defaults; the curated table on disk overrides where present.
CANONICAL_TO_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    "encryption_at_rest_missing":     {"pci": ["3.5.1", "3.5.1.2"], "nist": ["SC-28", "SC-28(1)"]},
    "encryption_in_transit_missing":  {"pci": ["4.2.1"],            "nist": ["SC-8", "SC-8(1)"]},
    "public_object_storage":          {"pci": ["1.4.1", "7.2.1"],   "nist": ["AC-3", "SC-7"]},
    "permissive_security_group":      {"pci": ["1.2.1", "1.4.1"],   "nist": ["SC-7", "SC-7(5)"]},
    "public_compute_endpoint":        {"pci": ["1.4.1", "1.4.2"],   "nist": ["SC-7", "AC-4"]},
    "iam_overly_permissive":          {"pci": ["7.2.2", "7.2.4"],   "nist": ["AC-2", "AC-6"]},
    "iam_root_or_admin_use":          {"pci": ["8.2.2", "8.6.3"],   "nist": ["AC-2", "AC-6(5)"]},
    "missing_logging_audit":          {"pci": ["10.2.1", "10.4.1"], "nist": ["AU-2", "AU-6", "AU-12"]},
    "missing_versioning_backup":      {"pci": ["12.10.1"],          "nist": ["CP-9", "CP-10"]},
    "hardcoded_secrets":              {"pci": ["8.3.2", "3.5.1"],   "nist": ["IA-5", "SC-28"]},
    "weak_kms_or_key_policy":         {"pci": ["3.6.1", "3.7.2"],   "nist": ["SC-12", "SC-13"]},
    "missing_resource_limits":        {"pci": ["6.4.1"],            "nist": ["SC-6", "CM-6"]},
    "missing_network_policy":         {"pci": ["1.2.1"],            "nist": ["SC-7", "AC-4"]},
    "permissive_rbac":                {"pci": ["7.2.1", "7.2.2"],   "nist": ["AC-2", "AC-6"]},
    "privileged_container":           {"pci": ["2.2.1"],            "nist": ["CM-6", "CM-7"]},
    "missing_pod_security":           {"pci": ["2.2.1", "6.4.1"],   "nist": ["CM-6", "CM-7"]},
    "missing_image_scan_or_pin":      {"pci": ["6.3.3", "11.3.1"],  "nist": ["RA-5", "SI-2"]},
    "missing_tls_for_ingress":        {"pci": ["4.2.1"],            "nist": ["SC-8", "SC-8(1)"]},
    "expensive_oversized_resource":   {"pci": [],                   "nist": ["CM-6"]},
    "data_transfer_anti_pattern":     {"pci": [],                   "nist": ["CM-6"]},
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ModuleRef:
    source: str           # "terra_ds" | "aws_samples" | "helm"
    repo_name: str
    path: str             # absolute path on disk
    iac_type: str         # "terraform" | "helm"
    module_id: Optional[str] = None

    def fingerprint(self) -> str:
        return hashlib.sha1(f"{self.source}|{self.path}".encode()).hexdigest()[:12]


@dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: str
    resource: str
    file_path: str
    message: str
    canonical_class: Optional[str] = None
    pci_controls: List[str] = field(default_factory=list)
    nist_controls: List[str] = field(default_factory=list)
    merged_scanners: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = SCAN_TIMEOUT_SEC) -> str:
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout or ""
    except subprocess.TimeoutExpired:
        LOG.warning("Timeout running %s", " ".join(cmd))
        return ""
    except FileNotFoundError:
        LOG.warning("Tool not found: %s", cmd[0])
        return ""
    except Exception as exc:
        LOG.warning("Error running %s: %s", " ".join(cmd), exc)
        return ""


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------

def sample_terra_modules(db_path: Path, src_root: Path, limit: int) -> List[ModuleRef]:
    if not db_path.exists():
        LOG.warning("TerraDS db not found at %s; skipping", db_path)
        return []
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        # The TerraDS schema is documented at https://github.com/.../terra_ds; we
        # use a schema-tolerant query that falls back to columns present in the
        # commonly distributed snapshot.
        try:
            cur.execute(
                """
                SELECT m.id, r.repo_name, m.path
                FROM modules m
                JOIN repos r ON m.repo_id = r.id
                WHERE m.num_resources >= 3
                ORDER BY m.num_resources DESC
                LIMIT ?;
                """,
                (limit * 4,),
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [t[0] for t in cur.fetchall()]
            LOG.warning("TerraDS schema unexpected; tables=%s", tables)
            rows = []
    finally:
        conn.close()

    candidates: List[ModuleRef] = []
    for mid, repo_name, rel_path in rows:
        repo_dir = src_root / repo_name
        module_dir = repo_dir / rel_path
        tf_files = list(module_dir.glob("*.tf")) if module_dir.exists() else []
        if tf_files:
            candidates.append(ModuleRef(
                source="terra_ds",
                repo_name=repo_name,
                path=str(module_dir),
                iac_type="terraform",
                module_id=str(mid),
            ))
    if len(candidates) <= limit:
        return candidates
    return random.sample(candidates, limit)


def collect_aws_samples(root: Path, limit: int) -> List[ModuleRef]:
    if not root.exists():
        LOG.warning("AWS Samples root missing: %s", root)
        return []
    seen: set[str] = set()
    modules: List[ModuleRef] = []
    for tf in root.rglob("*.tf"):
        parent = tf.parent.resolve()
        if str(parent) in seen:
            continue
        seen.add(str(parent))
        modules.append(ModuleRef(
            source="aws_samples",
            repo_name=parent.relative_to(root).parts[0] if parent != root else parent.name,
            path=str(parent),
            iac_type="terraform",
        ))
    if len(modules) <= limit:
        return modules
    return random.sample(modules, limit)


def collect_helm_charts(root: Path, limit: int) -> List[ModuleRef]:
    if not root.exists():
        LOG.warning("Helm charts root missing: %s", root)
        return []
    charts: List[ModuleRef] = []
    for chart in root.rglob("Chart.yaml"):
        charts.append(ModuleRef(
            source="helm",
            repo_name=chart.parent.name,
            path=str(chart.parent),
            iac_type="helm",
        ))
    if len(charts) <= limit:
        return charts
    return random.sample(charts, limit)


# ---------------------------------------------------------------------------
# Scanner adapters
# ---------------------------------------------------------------------------

def _safe_json(text: str) -> Any:
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Some scanners emit multiple JSON objects or a leading line.
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{") or line.startswith("["):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return None


def scan_with_checkov(path: str, iac_type: str) -> List[Finding]:
    framework = "helm" if iac_type == "helm" else "terraform"
    checkov_cmd = shutil.which("checkov") or shutil.which("checkov.cmd")

    if not checkov_cmd:
        LOG.warning("Checkov not found in PATH")
        return []

    out = run_cmd([checkov_cmd, "-d", path, "--framework", framework,
                   "--output", "json", "--quiet", "--soft-fail"])
    data = _safe_json(out)
    findings: List[Finding] = []
    if data is None:
        return findings
    # Checkov returns either a dict or a list of dicts depending on framework.
    blocks = data if isinstance(data, list) else [data]
    for block in blocks:
        results = (block or {}).get("results", {}) or {}
        for failed in results.get("failed_checks", []) or []:
            findings.append(Finding(
                scanner="checkov",
                rule_id=str(failed.get("check_id", "")),
                severity=str(failed.get("severity", "MEDIUM") or "MEDIUM"),
                resource=str(failed.get("resource", "")),
                file_path=str(failed.get("file_path", "")),
                message=str(failed.get("check_name", "")),
                raw=failed,
            ))
    return findings


def scan_with_tfsec(path: str) -> List[Finding]:
    out = run_cmd(["tfsec", "--no-color", "--format", "json",
                   "--soft-fail", path])
    data = _safe_json(out)
    if data is None:
        return []
    if isinstance(data, list):
        rows = data
    else:
        rows = data.get("results", []) or []
    findings: List[Finding] = []
    for row in rows:
        loc = row.get("location", {}) or {}
        findings.append(Finding(
            scanner="tfsec",
            rule_id=str(row.get("rule_id", "") or row.get("long_id", "")),
            severity=str(row.get("severity", "MEDIUM") or "MEDIUM"),
            resource=str(row.get("resource", "")),
            file_path=str(loc.get("filename", "")),
            message=str(row.get("description", "") or row.get("rule_description", "")),
            raw=row,
        ))
    return findings


def scan_with_trivy(path: str) -> List[Finding]:
    out = run_cmd(["trivy", "config", "--quiet", "--format", "json", path])
    data = _safe_json(out)
    if data is None:
        return []
    findings: List[Finding] = []
    for result in (data.get("Results", []) or []):
        target = str(result.get("Target", ""))
        for m in (result.get("Misconfigurations", []) or []):
            findings.append(Finding(
                scanner="trivy",
                rule_id=str(m.get("ID", "") or m.get("AVDID", "")),
                severity=str(m.get("Severity", "MEDIUM") or "MEDIUM"),
                resource=str(m.get("Resource", "") or m.get("Type", "")),
                file_path=target,
                message=str(m.get("Title", "") or m.get("Description", "")),
                raw=m,
            ))
    return findings


def scan_with_kics(path: str, work_root: Path) -> List[Finding]:
    out_dir = Path(tempfile.mkdtemp(prefix="kics-", dir=str(work_root)))
    try:
        run_cmd([
            "kics", "scan",
            "-p", path,
            "-o", str(out_dir),
            "--report-formats", "json",
            "--no-color",
            "--silent",
        ])
        report = out_dir / "results.json"
        if not report.exists():
            # Some KICS versions name the file differently.
            json_files = list(out_dir.glob("*.json"))
            if not json_files:
                return []
            report = json_files[0]
        try:
            data = json.loads(report.read_text())
        except Exception:
            return []
        findings: List[Finding] = []
        for query in (data.get("queries", []) or []):
            qname = str(query.get("query_name", ""))
            qid = str(query.get("query_id", ""))
            severity = str(query.get("severity", "MEDIUM") or "MEDIUM")
            for f in (query.get("files", []) or []):
                findings.append(Finding(
                    scanner="kics",
                    rule_id=qid,
                    severity=severity,
                    resource=str(f.get("resource_name", "") or f.get("resource_type", "")),
                    file_path=str(f.get("file_name", "")),
                    message=qname,
                    raw=f,
                ))
        return findings
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Canonicalization, dedup, control mapping
# ---------------------------------------------------------------------------

def map_rule_to_canonical(message: str, rule_id: str = "") -> Optional[str]:
    rid = (rule_id or "").upper()

    # 1. Rule-based mapping (deterministic)
    if rid in RULE_ID_MAP:
        return RULE_ID_MAP[rid]

    # 2. Message-based fallback
    blob = message.lower()

    # --- HIGH PRECISION FIRST ---

    # Networking
    if "0.0.0.0/0" in blob or "security group" in blob:
        return "permissive_security_group"

    # Encryption
    if "encryption" in blob or "kms" in blob:
        return "encryption_at_rest_missing"

    # Logging
    if "logging" in blob:
        return "missing_logging_audit"

    # Versioning
    if "versioning" in blob:
        return "missing_versioning_backup"

    # --- STORAGE ONLY IF PUBLIC ---
    if "public acl" in blob or "public access" in blob:
        return "public_object_storage"

    # --- PUBLIC READ (e.g. CKV_AWS_20) ---
    if "public read" in blob:
        return "public_object_storage"

    # --- LOW SIGNAL ---
    return "low_signal_misc"


def attach_controls(finding: Finding) -> None:
    klass = finding.canonical_class
    if not klass:
        return
    mapping = CANONICAL_TO_CONTROLS.get(klass, {})
    finding.pci_controls = list(mapping.get("pci", []))
    finding.nist_controls = list(mapping.get("nist", []))


def normalize_resource(resource: str) -> str:
    if not resource:
        return ""
    r = resource.lower()
    if "terraform security check" in r:
        return "terraform_generic"
    if "." in r:
        return r.split(".")[0]  # aws_s3_bucket.bad → aws_s3_bucket
    return r


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """Merge findings across scanners by canonical_class only."""
    bucket: Dict[str, Finding] = {}
    for f in findings:
        key = f.canonical_class
        existing = bucket.get(key)
        if existing:
            if _severity_rank(f.severity) > _severity_rank(existing.severity):
                existing.severity = f.severity
            existing.merged_scanners = list(set(existing.merged_scanners + [f.scanner]))
        else:
            f.merged_scanners = [f.scanner]
            bucket[key] = f
    return list(bucket.values())


def _severity_rank(s: str) -> int:
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get((s or "").upper(), 1)


# ---------------------------------------------------------------------------
# End-to-end per module
# ---------------------------------------------------------------------------

def scan_module(module: ModuleRef, work_root: Path) -> Dict[str, Any]:
    raw_findings: List[Finding] = []

    raw_findings.extend(scan_with_checkov(module.path, module.iac_type))
    if module.iac_type == "terraform":
        raw_findings.extend(scan_with_tfsec(module.path))
    raw_findings.extend(scan_with_trivy(module.path))
    raw_findings.extend(scan_with_kics(module.path, work_root))

    for f in raw_findings:
        f.canonical_class = map_rule_to_canonical(f.message, f.rule_id)
        attach_controls(f)

    canonical_findings = dedupe_findings(raw_findings)

    return {
        "meta": {
            "fingerprint": module.fingerprint(),
            "source": module.source,
            "repo_name": module.repo_name,
            "path": module.path,
            "iac_type": module.iac_type,
            "module_id": module.module_id,
        },
        "raw_findings": [serialize_finding(f) for f in raw_findings],
        "canonical_findings": [serialize_finding(f) for f in canonical_findings],
        "stats": {
            "n_raw": len(raw_findings),
            "n_canonical": len(canonical_findings),
            "by_class": _class_histogram(canonical_findings),
        },
    }


def serialize_finding(f: Finding) -> Dict[str, Any]:
    d = asdict(f)
    d.pop("raw", None)
    return d


def _class_histogram(findings: List[Finding]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        key = f.canonical_class or "unmapped"
        out[key] = out.get(key, 0) + 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Build IaC-Reviewer-Bench dataset")
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--total", type=int, default=1500)
    parser.add_argument("--terra-quota", type=int, default=1000)
    parser.add_argument("--aws-quota", type=int, default=250)
    parser.add_argument("--helm-quota", type=int, default=250)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--max-modules", type=int, default=None,
                        help="Optional hard cap useful for smoke tests")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    random.seed(args.seed)

    base = args.base
    out_root = args.out or (base / "output")
    out_root.mkdir(parents=True, exist_ok=True)

    terra_db = base / "terra_ds" / "terra_ds.sqlite"
    terra_src = base / "terra_ds" / "repos"
    aws_root = base / "aws-samples"
    helm_root = base / "helm-charts"

    work_root = out_root / "_work"
    work_root.mkdir(parents=True, exist_ok=True)

    LOG.info("Sampling Terraform modules from TerraDS (target=%d)", args.terra_quota)
    terra_modules = sample_terra_modules(terra_db, terra_src, args.terra_quota)
    LOG.info("  picked %d", len(terra_modules))

    LOG.info("Collecting AWS Samples modules (target=%d)", args.aws_quota)
    aws_modules = collect_aws_samples(aws_root, args.aws_quota)
    LOG.info("  picked %d", len(aws_modules))

    LOG.info("Collecting Helm charts (target=%d)", args.helm_quota)
    helm_modules = collect_helm_charts(helm_root, args.helm_quota)
    LOG.info("  picked %d", len(helm_modules))

    combined: List[ModuleRef] = terra_modules + aws_modules + helm_modules
    if len(combined) > args.total:
        combined = combined[: args.total]
    if args.max_modules:
        combined = combined[: args.max_modules]
    LOG.info("Total modules to scan: %d", len(combined))

    manifest: List[Dict[str, Any]] = []
    out_file = out_root / "iac_reviewer_bench_dataset.jsonl"
    with out_file.open("w") as f_out:
        for idx, module in enumerate(combined, start=1):
            t0 = time.time()
            try:
                record = scan_module(module, work_root)
            except Exception as exc:
                LOG.exception("Failed scanning %s: %s", module.path, exc)
                continue
            f_out.write(json.dumps(record) + "\n")
            f_out.flush()
            manifest.append(record)
            LOG.info("[%d/%d] %s raw=%d canon=%d (%.1fs)",
                     idx, len(combined), module.path,
                     record["stats"]["n_raw"], record["stats"]["n_canonical"],
                     time.time() - t0)

    summary = {
        "n_modules": len(manifest),
        "by_source": _count(manifest, lambda r: r["meta"]["source"]),
        "by_iac_type": _count(manifest, lambda r: r["meta"]["iac_type"]),
        "total_raw_findings": sum(r["stats"]["n_raw"] for r in manifest),
        "total_canonical_findings": sum(r["stats"]["n_canonical"] for r in manifest),
    }
    (out_root / "dataset_summary.json").write_text(json.dumps(summary, indent=2))
    LOG.info("Wrote %s and %s", out_file, out_root / "dataset_summary.json")
    shutil.rmtree(work_root, ignore_errors=True)
    return 0


def _count(records: Iterable[Dict[str, Any]], key) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in records:
        k = key(r)
        counts[k] = counts.get(k, 0) + 1
    return counts


if __name__ == "__main__":
    sys.exit(main())
