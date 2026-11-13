"""Run the current Redactor with and without the log-username tier; write harness checkpoints.

    python -m benchmarks.eval_log_usernames loghub_ssh OUT_DIR

Writes ``<corpus>_test_head-pattern.json`` and ``<corpus>_test_head-pattern-logusers.json``
(character offsets and types only), for ``benchmarks.cluster_bootstrap``.
"""

import json
import subprocess
import sys
from pathlib import Path

from benchmarks import corpora

from safestream_redactor.redactor import Redactor

corpus, out = sys.argv[1], Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
docs = corpora.load(corpus, "test").docs
to_canon = corpora.SAFESTREAM_TO_CANONICAL
commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
for name, kw in {"head-pattern": {}, "head-pattern-logusers": {"use_log_usernames": True}}.items():
    r = Redactor(backend="python", **kw)
    preds = [
        [
            [d.start, d.end, to_canon.get(d.entity_type.value, d.entity_type.value)]
            for d in r.detect(doc.text)
        ]
        for doc in docs
    ]
    (out / f"{corpus}_test_{name}.json").write_text(
        json.dumps({"commit": commit, "run": {"system": name, "kwargs": kw, "preds": preds}})
    )
    print(name, sum(len(p) for p in preds))
