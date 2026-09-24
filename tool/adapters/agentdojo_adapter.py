#!/usr/bin/env python3
"""Adapter: AgentDojo-style per-task result JSON -> AgentGuard-Audit `runs`/`reps` SQLite.

AgentDojo writes one JSON per (suite, user_task, injection_task, attack, defense) with the full
message list plus utility/security booleans. This maps that shape onto the auditor's log contract
so a published evaluation can be audited without rerunning it.

Interop spec (the log contract the auditor consumes):
  runs(case_id TEXT, reply TEXT, action_events TEXT, attack_success INT, utility_success INT)
  action_events = JSON list of {tool, params, blocked(bool), reason(str), memory_write(bool)}
  case file (jsonl): {id, needle|canary|secret|marker, exfil_to?}

Usage:
  python3 agentdojo_adapter.py --in <dir of AgentDojo *.json> --db out.sqlite \
      --cases cases.jsonl [--blocked-marker AbortAgentError ...]
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


def to_events(messages, blocked_markers):
    """AgentDojo message list -> audit action_events.

    A tool call is an executed event; a following tool response naming a blocked marker (the
    defense's abort/refusal string) flips the preceding call to blocked and keeps its text as
    the reason, so the auditor can attribute the block.
    """
    events, pending = [], None
    for m in messages:
        role = m.get("role")
        if role == "assistant":
            for tc in (m.get("tool_calls") or []):
                fn = tc.get("function", {})
                args = fn.get("arguments")
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {"_raw": args}
                pending = {"tool": fn.get("name", "?"), "params": args or {}, "blocked": False}
                events.append(pending)
        elif role == "tool":
            content = str(m.get("content", ""))
            if pending is not None and any(bm.lower() in content.lower() for bm in blocked_markers):
                pending["blocked"] = True
                pending["reason"] = content[:400]
            pending = None
    return events


class NeedleError(ValueError):
    """Raised when no usable marker can be resolved, rather than auditing against a task id."""


_BAD_NEEDLE_PREFIXES = ("injection_task", "user_task")


def resolve_needle(record, field, cid):
    """The string the attacker wants moved, as it will appear in tool arguments.

    A task identifier such as injection_task_0 never appears in tool arguments, so accepting one
    as the marker makes every cell read UNATTRIBUTED and the audit silently vacuous. Prefer the
    injected payload text, then an explicit field, and refuse anything that is only an id.
    """
    if field:
        v = record.get(field)
        if v:
            return v
        raise NeedleError(f"{cid}: --needle-field {field!r} is absent or empty")
    inj = record.get("injections")
    if isinstance(inj, dict) and inj:
        # AgentDojo maps each injection placeholder to the text actually planted in the tool output.
        return max((str(v) for v in inj.values()), key=len)
    for k in ("needle", "canary", "secret", "marker"):
        if record.get(k):
            return record[k]
    v = record.get("injection_task_id") or record.get("goal")
    if v and not str(v).startswith(_BAD_NEEDLE_PREFIXES):
        return v
    raise NeedleError(
        f"{cid}: no usable marker. AgentDojo's injection_task_id names the task, it is not the "
        f"string the attacker exfiltrates, so auditing against it would report every cell as "
        f"UNATTRIBUTED. Pass --needle-field, or use logs that carry 'injections'.")


def final_reply(messages):
    for m in reversed(messages):
        if m.get("role") == "assistant" and not m.get("tool_calls"):
            return m.get("content") or ""
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--cases", required=True)
    ap.add_argument("--blocked-marker", action="append",
                    default=["AbortAgentError", "blocked by", "not permitted", "security policy"])
    ap.add_argument("--id-field", default="id")
    ap.add_argument("--needle-field", default=None,
                    help="per-record field holding the string the attacker wants exfiltrated. "
                         "Default: the injected payload text under 'injections'.")
    ap.add_argument("--exfil-field", default=None,
                    help="per-record field holding the attacker destination, for goal binding")
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.execute("create table if not exists runs(case_id text, reply text, action_events text, attack_success int, utility_success int)")
    con.execute("create table if not exists reps(case_id text, rep int, attack_success int, utility_success int)")
    cases, n = {}, 0
    for f in sorted(Path(a.indir).glob("*.json")):
        d = json.loads(f.read_text())
        msgs = d.get("messages") or d.get("conversation") or []
        cid = str(d.get(a.id_field) or f.stem)
        con.execute("insert into runs values(?,?,?,?,?)",
                    (cid, final_reply(msgs), json.dumps(to_events(msgs, a.blocked_marker), ensure_ascii=False),
                     int(bool(d.get("security"))), int(bool(d.get("utility")))))
        needle = resolve_needle(d, a.needle_field, cid)
        case = {"id": cid, "needle": str(needle)}
        if a.exfil_field and d.get(a.exfil_field):
            case["exfil_to"] = d[a.exfil_field]
        cases[cid] = case
        n += 1
    con.commit()
    con.close()
    with open(a.cases, "w", encoding="utf-8") as fh:
        for c in cases.values():
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")
    print(f"wrote {n} runs to {a.db} and {len(cases)} cases to {a.cases}")


if __name__ == "__main__":
    main()
