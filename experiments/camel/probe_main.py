# Counterfactual label-flip probe around CaMeL's own security policies.
#
# CaMeL decides each side-effecting call with SecurityPolicyEngine.check_policy, which reads the
# capabilities its interpreter attaches to values: is_trusted for where a value came from,
# is_public and can_readers_read_value for who may read it. This wrapper leaves that decision
# untouched and, whenever it denies a call, re-evaluates the same call with those capability
# predicates forced to the permissive answer. A denial that disappears was grounded in the data
# labels, which is what the paper's replay probe asserts; one that stands was not. Nothing else
# about CaMeL changes, and no extra model call is made.
#
# Usage is the upstream entry point with this wrapper installed first:
#   uv run --env-file .env probe_main.py openai:gpt-4o-mini-2024-07-18 --run-attack \
#       --replay-with-policies --suites banking
# Records land in probe_records.jsonl next to this file.
from __future__ import annotations

import contextlib
import json
import os
import threading
from pathlib import Path

from main import main  # noqa: E402  imported first, see note above

import camel.capabilities as caps
import camel.security_policy as sp
from camel.pipeline_elements.security_policies import banking as bank_pol
from camel.pipeline_elements.security_policies import slack as slack_pol
from camel.pipeline_elements.security_policies import travel as travel_pol
from camel.pipeline_elements.security_policies import workspace as ws_pol

OUT = Path(os.environ.get("PROBE_OUT", Path(__file__).parent / "probe_records.jsonl"))
_lock = threading.Lock()
_MODULES = (sp, bank_pol, slack_pol, travel_pol, ws_pol, caps)


_YES = lambda *_a, **_k: True  # noqa: E731
# Each group forces one kind of label permissive, so a denial is traced to the label it reads:
# the source label (is_trusted) or the reader label (is_public, can_readers_read_value).
GROUPS = {"all": ("is_trusted", "is_public", "can_readers_read_value"),
          "source": ("is_trusted",),
          "readers": ("is_public", "can_readers_read_value")}


@contextlib.contextmanager
def _public_labels(group="all"):
    """Same call, with the labels of one group removed: those predicates answer permissively."""
    patches = {name: _YES for name in GROUPS[group]}
    saved = []
    for mod in _MODULES:
        for name, fn in patches.items():
            if hasattr(mod, name):
                saved.append((mod, name, getattr(mod, name)))
                setattr(mod, name, fn)
    try:
        yield
    finally:
        for mod, name, fn in saved:
            setattr(mod, name, fn)


def _install():
    orig = sp.SecurityPolicyEngine.check_policy

    def patched(self, tool_name, kwargs, dependencies):
        deps = list(dependencies)
        res = orig(self, tool_name, kwargs, deps)
        rec = {"engine": type(self).__name__, "tool": tool_name,
               "decision": type(res).__name__, "reason": getattr(res, "reason", "")}
        if isinstance(res, sp.Denied):
            for group in GROUPS:
                key = "counterfactual" if group == "all" else f"counterfactual_{group}"
                try:
                    with _public_labels(group):
                        alt = orig(self, tool_name, kwargs, deps)
                    rec[key] = type(alt).__name__
                    rec[key + "_reason"] = getattr(alt, "reason", "")
                except Exception as e:  # a policy that cannot be re-evaluated is recorded, not hidden
                    rec[key] = "ERROR"
                    rec[key + "_reason"] = repr(e)[:200]
        with _lock:
            with OUT.open("a") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return res

    for cls in (sp.SecurityPolicyEngine, *sp.SecurityPolicyEngine.__subclasses__()):
        cls.check_policy = patched


_install()

if __name__ == "__main__":
    import cyclopts

    app = cyclopts.App()
    app.default(main)
    app()
