"""Time the model on THIS machine: one attacker call, one rewrite, then a few full documents.

    SHIELD_BACKEND=llm LOOP_LLM_BASE_URL=http://127.0.0.1:8080/v1 python3 -m shield.benchmark

Run it on LinuxONE first thing: it tells you whether the model is fast enough, and the
printed numbers (with `uname -m` = s390x) are the "measured on LinuxONE" proof for the video.
"""
import argparse
import platform
import statistics
import time

from . import config, llm
from .attacker import is_leak, llm_attack
from .data_gen import generate
from .pipeline import protect
from .rewriter import llm_rewrite
from .vault import Vault


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--docs", type=int, default=2, help="full documents to run through the loop")
    args = ap.parse_args()
    print(f"machine={platform.machine()}  attacker={config.LOOP_LLM.base_url}  "
          f"rewriter={config.REWRITE_LLM.base_url}")

    doc = Vault().swap(generate(1, seed=99)[0]["text"])
    t = time.perf_counter()
    try:
        guesses = llm_attack(doc, config.LOOP_LLM)
    except llm.LLMError as exc:
        raise SystemExit(f"Model server not reachable or reply unparseable:\n  {exc}")
    print(f"\n1 attacker call: {time.perf_counter() - t:.1f}s, {len(guesses)} valid guesses")
    for g in guesses:
        print(f"   {g.attribute:<13} {str(g.value):<12} conf={g.confidence:.2f}  evidence={g.evidence}")
    if not guesses:
        print("   (no valid guesses: check the raw reply format; small models may need prompt tweaks)")

    leaks = [g for g in guesses if is_leak(g)]
    if config.REWRITE_MODE != "ai":
        print("rewrite: suppression (leaking phrases -> labels like [AGE]; no model call)")
    elif leaks:
        t = time.perf_counter()
        try:
            llm_rewrite(doc, leaks, config.REWRITE_LLM)
            print(f"1 rewrite call:  {time.perf_counter() - t:.1f}s")
        except (llm.LLMError, ValueError) as exc:
            print(f"1 rewrite call:  {time.perf_counter() - t:.1f}s, UNUSABLE reply ({exc}); loop will suppress instead")

    times = []
    for rec in generate(args.docs, seed=98):
        r = protect(rec["text"], backend="llm")
        times.append(r.seconds)
        print(f"\nfull document: {r.seconds:.1f}s, {len(r.rounds)} rounds, passed={r.passed}"
              + (f"  ERROR: {r.error}" if r.error else ""))
        for rd in r.rounds:
            found = ", ".join(f"{g.attribute}={g.value} {g.evidence}" for g in rd.leaks) or "no leaks"
            how = "AI edits" if rd.used_ai_rewrite else ("suppressed" if rd.leaks else "-")
            print(f"  round {rd.number} ({rd.seconds:.0f}s, {how}): {found}")
        print("  final text: " + r.text.replace("\n", " ")[:400])
    print(f"\nmedian per document: {statistics.median(times):.1f}s on {platform.machine()}")


if __name__ == "__main__":
    main()
