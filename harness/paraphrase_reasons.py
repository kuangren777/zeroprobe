#!/usr/bin/env python3
"""Robustness of reason attribution: paraphrase every block reason with an LLM and re-audit.

For each (model, arm) with blocked events on suite S, writes a copy of the DB whose reasons are
paraphrased (meaning preserved, wording changed) and reports the verdict before and after.
"""
import concurrent.futures as cf, json, shutil, sqlite3, sys, urllib.request, os, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tool")); sys.path.insert(0, str(ROOT / "harness"))
import agentguard_audit as ag
from analyze import REGISTRY, MODELS
RES = ROOT / "experiments/audit-validity/results"; OUT = ROOT / "experiments/audit-validity/paraphrase" / os.environ.get("PARA_VARIANT", "mild")
KEY = os.environ["AGENTBENCH_KEY"]; URL = os.environ.get("AGENTBENCH_URL", "https://api.openai.com/v1/chat/completions")
VARIANT = os.environ.get("PARA_VARIANT", "mild")
PROMPT_PLAIN = ("Rewrite the following security-policy log message as one plain English sentence for a non-technical user. "
                "Keep the meaning, do not quote field names, labels, code or values in quotes, and output only the sentence.\n\n{r}")
PROMPT = ("Rewrite the following security-policy log message in different words for a human operator. Keep every fact "
          "and the meaning, do not add information, output only the rewritten message.\n\n{r}")
OUT.mkdir(parents=True, exist_ok=True)
cache_path = OUT / "cache.json"
cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}

def para(r):
    if r in cache: return cache[r]
    body = json.dumps({"model": "gpt-4.1-mini-2025-04-14", "messages": [{"role": "user", "content": (PROMPT_PLAIN if VARIANT == "plain" else PROMPT).format(r=r)}], "temperature": 0, "max_tokens": 200}).encode()
    for i in range(6):
        try:
            req = urllib.request.Request(URL, data=body, headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
            out = json.load(urllib.request.urlopen(req, timeout=120))["choices"][0]["message"]["content"].strip()
            return out
        except Exception:
            time.sleep(3 * 2 ** i)
    raise RuntimeError("paraphrase failed")

cases = ag._load_cases(str(ROOT / "experiments/audit-validity/cases/S.jsonl"))
reasons = set()
targets = []
for m in MODELS[:3]:
    for arm in ["const", "ifc", "partial", "allow", "judge"]:
        src = RES / f"S__{arm}__{m}.sqlite"
        targets.append((m, arm, src))
        for (ae,) in sqlite3.connect(str(src)).execute("select action_events from runs"):
            for e in json.loads(ae or "[]"):
                if e.get("blocked"): reasons.add(e.get("reason", ""))
todo = [r for r in reasons if r not in cache]
with cf.ThreadPoolExecutor(8) as ex:
    for r, p in zip(todo, ex.map(para, todo)): cache[r] = p
cache_path.write_text(json.dumps(cache, indent=1, ensure_ascii=False))
rows = []
for m, arm, src in targets:
    dst = OUT / src.name
    shutil.copy(src, dst)
    con = sqlite3.connect(str(dst))
    for rid, ae in list(con.execute("select rowid, action_events from runs")):
        evs = json.loads(ae or "[]")
        for e in evs:
            if e.get("blocked"): e["reason"] = cache[e.get("reason", "")]
        con.execute("update runs set action_events=? where rowid=?", (json.dumps(evs, ensure_ascii=False), rid))
    con.commit(); con.close()
    before = ag.compute_metrics(ag.audit_one(str(src), cases, REGISTRY[arm]))["completeness"]
    after = ag.compute_metrics(ag.audit_one(str(dst), cases, REGISTRY[arm]))["completeness"]
    rows.append({"model": m, "arm": arm, "before": before, "after": after})
    print(m, arm, before, "->", after)
ifc_r = [r for r in reasons if "label check" in r]
(OUT / "summary.json").write_text(json.dumps({"variant": VARIANT, "n_reasons": len(reasons), "n_ifc_reasons": len(ifc_r),
    "ifc_keyword_kept": sum(ag._is_attributed(cache[r]) for r in ifc_r),
    "other_keyword_gained": sum(ag._is_attributed(cache[r]) for r in reasons if r not in ifc_r),
    "rows": rows}, indent=1))
ex_ifc = next(r for r in reasons if "label check" in r)
print("example:", ex_ifc, "=>", cache[ex_ifc])
