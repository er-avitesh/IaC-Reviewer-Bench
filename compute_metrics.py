#!/usr/bin/env python3
"""
compute_metrics.py
==================

Consumes the dataset (oracle ground truth) and the per-(task,model) JSONL
outputs from run_eval.py, then computes:

  - T1: per-class and macro Precision / Recall / F1
  - T2: TP rate, FP-suppression rate, confusion matrix vs oracle
  - T3: strict and relaxed control-mapping accuracy (PCI + NIST)
  - Cost-per-true-finding for each model
  - Cohen's kappa (pairwise) and Fleiss' kappa across models

Outputs a single metrics_report.json plus a metrics_table.md ready for the
paper's Table III replacement.

Author : Avitesh Kesharwani, MS UNCC, IEEE Senior Member
"""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def jread(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    p = _safe_div(tp, tp + fp)
    r = _safe_div(tp, tp + fn)
    f = _safe_div(2 * p * r, p + r) if (p + r) else 0.0
    return p, r, f


# ---------------------------------------------------------------------------
# Indexing the oracle
# ---------------------------------------------------------------------------

def index_oracle(dataset: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Index oracle records by module fingerprint."""
    return {r["meta"]["fingerprint"]: r for r in dataset}


def oracle_class_set(record: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for f in record.get("canonical_findings", []):
        c = f.get("canonical_class")
        if c:
            out.add(c)
    return out


def oracle_pair_set(record: Dict[str, Any]) -> Set[Tuple[str, str]]:
    """class + resource (last token) for resource-level scoring."""
    out: Set[Tuple[str, str]] = set()
    for f in record.get("canonical_findings", []):
        c = f.get("canonical_class")
        if not c:
            continue
        res = (f.get("resource") or "").split(".")[-1]
        out.add((c, res))
    return out


def oracle_alert_truth(record: Dict[str, Any]) -> Dict[Tuple[str, str, str], str]:
    """
    For Task 2 evaluation: classify each raw scanner alert as TRUE_POSITIVE
    if it survives canonicalization, otherwise FALSE_POSITIVE/DUPLICATE.
    Key is (scanner, rule_id, resource_tail).
    """
    canon_keys: Set[Tuple[str, str]] = set()
    for f in record.get("canonical_findings", []):
        canon_keys.add((f.get("canonical_class") or "", (f.get("resource") or "").split(".")[-1]))

    truth: Dict[Tuple[str, str, str], str] = {}
    seen_canon: Set[Tuple[str, str]] = set()
    for f in record.get("raw_findings", []):
        key = (f.get("scanner", ""), f.get("rule_id", ""),
               (f.get("resource") or "").split(".")[-1])
        ck = (f.get("canonical_class") or "", (f.get("resource") or "").split(".")[-1])
        if ck in canon_keys:
            if ck in seen_canon:
                truth[key] = "DUPLICATE"
            else:
                truth[key] = "TRUE_POSITIVE"
                seen_canon.add(ck)
        else:
            truth[key] = "FALSE_POSITIVE"
    return truth


def oracle_compliance(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "canonical_class": f.get("canonical_class"),
            "resource": f.get("resource"),
            "pci": set(f.get("pci_controls", []) or []),
            "nist": set(f.get("nist_controls", []) or []),
        }
        for f in record.get("canonical_findings", [])
        if f.get("canonical_class")
    ]


# ---------------------------------------------------------------------------
# T1 metrics
# ---------------------------------------------------------------------------

def task1_metrics(eval_rows: List[Dict[str, Any]],
                  oracle: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    per_class_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    macro_tp = macro_fp = macro_fn = 0
    res_tp = res_fp = res_fn = 0
    cost_total = 0.0
    n_modules = 0

    for row in eval_rows:
        fp_id = row["module_meta"]["fingerprint"]
        oracle_rec = oracle.get(fp_id)
        if oracle_rec is None:
            continue
        n_modules += 1
        cost_total += float(row.get("cost_usd", 0.0) or 0.0)

        gold_classes = oracle_class_set(oracle_rec)
        gold_pairs   = oracle_pair_set(oracle_rec)

        pred = row.get("parsed") or {}
        findings = pred.get("findings", []) if isinstance(pred, dict) else []
        pred_classes: Set[str] = set()
        pred_pairs:   Set[Tuple[str, str]] = set()
        for f in findings:
            if not isinstance(f, dict):
                continue
            c = f.get("misconfig_class") or f.get("canonical_class")
            if not c:
                continue
            pred_classes.add(c)
            res = (f.get("resource") or "").split(".")[-1]
            pred_pairs.add((c, res))

        # Class-level
        for c in pred_classes | gold_classes:
            if c in pred_classes and c in gold_classes:
                per_class_counts[c]["tp"] += 1; macro_tp += 1
            elif c in pred_classes:
                per_class_counts[c]["fp"] += 1; macro_fp += 1
            else:
                per_class_counts[c]["fn"] += 1; macro_fn += 1

        # Resource-level
        res_tp += len(pred_pairs & gold_pairs)
        res_fp += len(pred_pairs - gold_pairs)
        res_fn += len(gold_pairs - pred_pairs)

    per_class: Dict[str, Dict[str, float]] = {}
    for c, cnt in per_class_counts.items():
        p, r, f = prf(cnt["tp"], cnt["fp"], cnt["fn"])
        per_class[c] = {"precision": p, "recall": r, "f1": f, **cnt}

    macro_p, macro_r, macro_f = prf(macro_tp, macro_fp, macro_fn)
    res_p,   res_r,   res_f   = prf(res_tp,   res_fp,   res_fn)
    cost_per_tp = _safe_div(cost_total, macro_tp)

    return {
        "n_modules": n_modules,
        "macro": {"precision": macro_p, "recall": macro_r, "f1": macro_f,
                  "tp": macro_tp, "fp": macro_fp, "fn": macro_fn},
        "resource_level": {"precision": res_p, "recall": res_r, "f1": res_f,
                           "tp": res_tp, "fp": res_fp, "fn": res_fn},
        "per_class": per_class,
        "cost_total_usd": cost_total,
        "cost_per_true_finding_usd": cost_per_tp,
    }


# ---------------------------------------------------------------------------
# T2 metrics
# ---------------------------------------------------------------------------

VALID_T2_LABELS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE", "OUT_OF_SCOPE"}


def task2_metrics(eval_rows: List[Dict[str, Any]],
                  oracle: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    confusion: Dict[Tuple[str, str], int] = defaultdict(int)
    n_alerts = 0
    n_correct = 0
    tp_recall_num = tp_recall_den = 0
    fp_suppress_num = fp_suppress_den = 0
    cost_total = 0.0

    for row in eval_rows:
        fp_id = row["module_meta"]["fingerprint"]
        oracle_rec = oracle.get(fp_id)
        if oracle_rec is None:
            continue
        cost_total += float(row.get("cost_usd", 0.0) or 0.0)

        truth = oracle_alert_truth(oracle_rec)

        pred = row.get("parsed") or {}
        decisions = pred.get("decisions", []) if isinstance(pred, dict) else []
        for d in decisions:
            if not isinstance(d, dict):
                continue
            key = (d.get("scanner", ""), d.get("rule_id", ""),
                   (d.get("resource") or "").split(".")[-1])
            label = (d.get("decision") or "").upper().replace("-", "_").replace(" ", "_")
            if label not in VALID_T2_LABELS:
                continue
            n_alerts += 1
            t = truth.get(key)
            if t is None:
                continue
            confusion[(t, label)] += 1
            if t == label:
                n_correct += 1
            if t == "TRUE_POSITIVE":
                tp_recall_den += 1
                if label == "TRUE_POSITIVE":
                    tp_recall_num += 1
            if t in ("FALSE_POSITIVE", "DUPLICATE"):
                fp_suppress_den += 1
                if label in ("FALSE_POSITIVE", "DUPLICATE"):
                    fp_suppress_num += 1

    return {
        "n_alerts_scored": n_alerts,
        "exact_accuracy": _safe_div(n_correct, n_alerts),
        "true_positive_recall": _safe_div(tp_recall_num, tp_recall_den),
        "false_positive_suppression_rate": _safe_div(fp_suppress_num, fp_suppress_den),
        "confusion": {f"{k[0]}__as__{k[1]}": v for k, v in confusion.items()},
        "cost_total_usd": cost_total,
    }


# ---------------------------------------------------------------------------
# T3 metrics
# ---------------------------------------------------------------------------

def _set_overlap(a: Set[str], b: Set[str]) -> Tuple[int, int, int]:
    return len(a & b), len(a - b), len(b - a)


def task3_metrics(eval_rows: List[Dict[str, Any]],
                  oracle: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    pci_strict_correct = pci_relaxed_correct = pci_total = 0
    nist_strict_correct = nist_relaxed_correct = nist_total = 0
    cost_total = 0.0

    for row in eval_rows:
        fp_id = row["module_meta"]["fingerprint"]
        oracle_rec = oracle.get(fp_id)
        if oracle_rec is None:
            continue
        cost_total += float(row.get("cost_usd", 0.0) or 0.0)

        gold_by_class: Dict[str, Dict[str, Set[str]]] = {}
        for entry in oracle_compliance(oracle_rec):
            c = entry["canonical_class"]
            gold_by_class.setdefault(c, {"pci": set(), "nist": set()})
            gold_by_class[c]["pci"]  |= entry["pci"]
            gold_by_class[c]["nist"] |= entry["nist"]

        pred = row.get("parsed") or {}
        mappings = pred.get("mappings", []) if isinstance(pred, dict) else []
        for m in mappings:
            if not isinstance(m, dict):
                continue
            c = m.get("misconfig_class")
            if not c or c not in gold_by_class:
                continue
            gold = gold_by_class[c]
            pred_pci  = set(m.get("pci_controls", []) or [])
            pred_nist = set(m.get("nist_controls", []) or [])

            pci_total += 1
            if pred_pci == gold["pci"] and gold["pci"]:
                pci_strict_correct += 1
            if pred_pci & gold["pci"]:
                pci_relaxed_correct += 1

            nist_total += 1
            if pred_nist == gold["nist"] and gold["nist"]:
                nist_strict_correct += 1
            if pred_nist & gold["nist"]:
                nist_relaxed_correct += 1

    return {
        "pci_strict_accuracy":   _safe_div(pci_strict_correct,  pci_total),
        "pci_relaxed_accuracy":  _safe_div(pci_relaxed_correct, pci_total),
        "nist_strict_accuracy":  _safe_div(nist_strict_correct,  nist_total),
        "nist_relaxed_accuracy": _safe_div(nist_relaxed_correct, nist_total),
        "n_findings_scored": pci_total,
        "cost_total_usd": cost_total,
    }


# ---------------------------------------------------------------------------
# Agreement: Cohen's and Fleiss' kappa on T1 class predictions
# ---------------------------------------------------------------------------

def cohens_kappa(a: List[int], b: List[int]) -> float:
    n = len(a)
    if n == 0:
        return 0.0
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    pa = sum(a) / n
    pb = sum(b) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    return _safe_div(po - pe, 1 - pe)


def fleiss_kappa(matrix: List[List[int]]) -> float:
    """matrix: rows = subjects, cols = categories; cell = #raters assigning."""
    if not matrix:
        return 0.0
    N = len(matrix)
    n = sum(matrix[0])
    if n <= 1:
        return 0.0
    k = len(matrix[0])
    p = [sum(matrix[i][j] for i in range(N)) / (N * n) for j in range(k)]
    P = [(sum(c * c for c in row) - n) / (n * (n - 1)) for row in matrix]
    P_bar = sum(P) / N
    Pe_bar = sum(pj * pj for pj in p)
    return _safe_div(P_bar - Pe_bar, 1 - Pe_bar)


def agreement_t1(per_model_rows: Dict[str, List[Dict[str, Any]]],
                 oracle: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    # Build per-model class membership vectors over the union of (module, class).
    universe_classes: Set[str] = set()
    for rows in per_model_rows.values():
        for r in rows:
            pred = r.get("parsed") or {}
            for f in (pred.get("findings", []) if isinstance(pred, dict) else []):
                if isinstance(f, dict):
                    c = f.get("misconfig_class") or f.get("canonical_class")
                    if c:
                        universe_classes.add(c)
    for rec in oracle.values():
        universe_classes |= oracle_class_set(rec)

    module_ids: List[str] = sorted(oracle.keys())
    class_list = sorted(universe_classes)

    vectors: Dict[str, List[int]] = {}
    for mk, rows in per_model_rows.items():
        by_fp: Dict[str, Set[str]] = {}
        for r in rows:
            fp = r["module_meta"]["fingerprint"]
            pred = r.get("parsed") or {}
            classes: Set[str] = set()
            for f in (pred.get("findings", []) if isinstance(pred, dict) else []):
                if isinstance(f, dict):
                    c = f.get("misconfig_class") or f.get("canonical_class")
                    if c:
                        classes.add(c)
            by_fp[fp] = classes
        vec: List[int] = []
        for mid in module_ids:
            present = by_fp.get(mid, set())
            for c in class_list:
                vec.append(1 if c in present else 0)
        vectors[mk] = vec

    pairwise: Dict[str, float] = {}
    keys = list(vectors.keys())
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            pairwise[f"{keys[i]}__vs__{keys[j]}"] = cohens_kappa(vectors[keys[i]], vectors[keys[j]])

    # Fleiss kappa: each "subject" is a (module, class) cell with binary categories.
    matrix: List[List[int]] = []
    n_keys = len(keys)
    L = len(vectors[keys[0]]) if keys else 0
    for idx in range(L):
        ones = sum(vectors[k][idx] for k in keys)
        zeros = n_keys - ones
        matrix.append([zeros, ones])
    fleiss = fleiss_kappa(matrix) if matrix else 0.0

    return {"pairwise_cohens_kappa": pairwise, "fleiss_kappa": fleiss}


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description="Compute IaC-Reviewer-Bench metrics")
    p.add_argument("--dataset", type=Path, required=True)
    p.add_argument("--results-dir", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--models", nargs="+",
                   default=["gpt-5.5", "claude-sonnet-4.6", "gemini-2.5-pro"])
    args = p.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    dataset = jread(args.dataset)
    oracle = index_oracle(dataset)

    report: Dict[str, Any] = {"models": {}, "agreement": {}}
    per_model_t1_rows: Dict[str, List[Dict[str, Any]]] = {}

    for mk in args.models:
        m_report: Dict[str, Any] = {}
        for task in ("task1", "task2", "task3"):
            path = args.results_dir / f"{task}_{mk}.jsonl"
            if not path.exists():
                m_report[task] = {"error": f"missing {path}"}
                continue
            rows = jread(path)
            if task == "task1":
                m_report[task] = task1_metrics(rows, oracle)
                per_model_t1_rows[mk] = rows
            elif task == "task2":
                m_report[task] = task2_metrics(rows, oracle)
            else:
                m_report[task] = task3_metrics(rows, oracle)
        report["models"][mk] = m_report

    if per_model_t1_rows:
        report["agreement"] = agreement_t1(per_model_t1_rows, oracle)

    (args.out / "metrics_report.json").write_text(json.dumps(report, indent=2))

    # Markdown table for the paper
    lines = ["# IaC-Reviewer-Bench Metrics", "",
             "| Metric | " + " | ".join(args.models) + " |",
             "|" + "---|" * (len(args.models) + 1)]
    rows = [
        ("T1 Macro F1",  lambda r: r["task1"]["macro"]["f1"]),
        ("T1 Resource F1", lambda r: r["task1"]["resource_level"]["f1"]),
        ("T2 TP Recall", lambda r: r["task2"]["true_positive_recall"]),
        ("T2 FP Suppression", lambda r: r["task2"]["false_positive_suppression_rate"]),
        ("T3 PCI Strict",  lambda r: r["task3"]["pci_strict_accuracy"]),
        ("T3 NIST Strict", lambda r: r["task3"]["nist_strict_accuracy"]),
        ("Cost / true finding (USD)", lambda r: r["task1"]["cost_per_true_finding_usd"]),
    ]
    for label, fn in rows:
        cells = []
        for mk in args.models:
            try:
                v = fn(report["models"][mk])
                cells.append(f"{v:.3f}" if isinstance(v, float) else str(v))
            except Exception:
                cells.append("n/a")
        lines.append(f"| {label} | " + " | ".join(cells) + " |")

    (args.out / "metrics_table.md").write_text("\n".join(lines) + "\n")
    print("Wrote metrics_report.json and metrics_table.md")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
