"""Load AgentDojo's prompt-injection detector from a local copy of the published checkpoint.

AgentDojo's `transformers_pi_detector` defense instantiates
`protectai/deberta-v3-base-prompt-injection-v2` by hub name. The hub is not reachable from this
host, so the weights were fetched once through a mirror into LOCAL and this module points the
class at that directory. It also gives the classifier the 512-token window of its own model card,
which the stock pipeline leaves unset, since a tool output of a few thousand tokens otherwise
costs tens of seconds per call. The decision rule, threshold and mode are unchanged.

Passed to the benchmark with `--module-to-load harness.ad_local_detector`.
"""
from __future__ import annotations
import os

import torch
from transformers import AutoTokenizer, pipeline

from agentdojo.agent_pipeline import pi_detector

# Set PI_DETECTOR_PATH to a local copy of the checkpoint when the hub is unreachable.
LOCAL = os.environ.get("PI_DETECTOR_PATH", "protectai/deberta-v3-base-prompt-injection-v2")
MAX_LEN = 512

_orig = pi_detector.TransformersBasedPIDetector.__init__


def _patched(self, model_name: str = LOCAL, *args, **kwargs):
    _orig(self, LOCAL, *args, **kwargs)
    torch.set_num_threads(int(os.environ.get("PI_DETECTOR_THREADS", "8")))
    tok = AutoTokenizer.from_pretrained(LOCAL, use_fast=True)
    self.pipeline = pipeline("text-classification", model=LOCAL, tokenizer=tok,
                             truncation=True, max_length=MAX_LEN)


pi_detector.TransformersBasedPIDetector.__init__ = _patched
