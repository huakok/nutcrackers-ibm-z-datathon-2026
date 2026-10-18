"""The experiment: how much can an attacker still infer after each method?

Three conditions per document:
  raw     the original text (how much is exposed with no protection)
  basic   names/IDs swapped for placeholders only (what Presidio-style tools do)
  loop    our attack-tested loop

For each, the EVALUATION attacker (EVAL_LLM, ideally stronger than the loop's own
attacker) guesses the attributes, and we mark it against the answer key.

    python -m shield.evaluate --data data/test.jsonl                 # rule-based stand-in
    SHIELD_BACKEND=llm python -m shield.evaluate --data data/test.jsonl --limit 30

Writes results/summary.json, results/per_doc.jsonl and (if matplotlib is installed) charts.
"""
import argparse
import json
import statistics
import time
from pathlib import Path

from . import config, llm
from .attacker import attack
from .pipeline import protect
from .schema import ATTRIBUTES
from .scoring import score, word_retention
from .vault import Vault

CONDITIONS = ["raw", "basic", "loop"]
LABELS = {"raw": "No redaction", "basic": "Basic redaction", "loop": "Attack-tested (ours)"}


def run(records: list[dict], backend: str) -> tuple[dict, list[dict]]:
    per_doc = []
    for i, rec in enumerate(records, 1):
        try:
            row = _run_one(rec, backend)
        except llm.LLMError as exc:
            # Excluded from the scores (and counted), never scored as "attacker found nothing".
            row = {"id": rec["id"], "error": str(exc)}
            print(f"[{i}/{len(records)}] {rec['id']} SKIPPED: {exc}", flush=True)
        else:
            print(f"[{i}/{len(records)}] {rec['id']} rounds={row['rounds']} "
                  f"passed={row['passed']} {row['loop_seconds']}s", flush=True)
        per_doc.append(row)
    return summarise(per_doc), per_doc


def _run_one(rec: dict, backend: str) -> dict:
    eval_attack = lambda text: attack(text, config.EVAL_LLM, backend)
    basic_text = Vault().swap(rec["text"])
    result = protect(rec["text"], backend=backend)
    return {
        "id": rec["id"], "doc_type": rec["doc_type"], "revealed": rec["revealed"],
        "scores": {
            "raw": score(eval_attack(rec["text"]), rec),
            "basic": score(eval_attack(basic_text), rec),
            "loop": score(eval_attack(result.text), rec),
        },
        "rounds": len(result.rounds), "passed": result.passed, "loop_error": result.error,
        "loop_seconds": round(result.seconds, 3),
        "retention": round(word_retention(basic_text, result.text), 3),
        "final_text": result.text,
    }


def summarise(all_rows: list[dict]) -> dict:
    per_doc = [r for r in all_rows if "error" not in r]
    if not per_doc:
        raise SystemExit("Every document failed: check the model servers (see the SKIPPED lines).")

    def accuracy(cond, attribute=None):
        hits = [ok for r in per_doc for a, ok in r["scores"][cond].items()
                if attribute is None or a == attribute]
        return round(sum(hits) / len(hits), 3) if hits else None

    return {
        "documents": len(per_doc),
        "skipped_documents": len(all_rows) - len(per_doc),
        "backend": config.BACKEND,
        "attacker_accuracy": {c: accuracy(c) for c in CONDITIONS},
        "by_attribute": {a: {c: accuracy(c, a) for c in CONDITIONS} for a in ATTRIBUTES},
        "pass_rate": round(sum(r["passed"] for r in per_doc) / len(per_doc), 3),
        "mean_rounds": round(statistics.mean(r["rounds"] for r in per_doc), 2),
        "median_loop_seconds": round(statistics.median(r["loop_seconds"] for r in per_doc), 3),
        "mean_word_retention": round(statistics.mean(r["retention"] for r in per_doc), 3),
    }


def print_summary(s: dict) -> None:
    print(f"\n=== {s['documents']} documents ({s['skipped_documents']} skipped), backend={s['backend']} ===")
    print(f"{'Attribute':<14}" + "".join(f"{LABELS[c]:>24}" for c in CONDITIONS))
    for a, row in s["by_attribute"].items():
        print(f"{a:<14}" + "".join(f"{'-' if row[c] is None else f'{row[c]:.0%}':>24}" for c in CONDITIONS))
    print(f"{'OVERALL':<14}" + "".join(f"{s['attacker_accuracy'][c]:>24.0%}" for c in CONDITIONS))
    print(f"\nPassed (attacker found no confident leak): {s['pass_rate']:.0%}")
    print(f"Mean rounds: {s['mean_rounds']}   Median loop time: {s['median_loop_seconds']}s   "
          f"Word retention vs basic: {s['mean_word_retention']:.0%}")
    if s["backend"] == "heuristic":
        print("\nNOTE: rule-based stand-in attacker. These numbers test the plumbing only; "
              "they are NOT results. Run with SHIELD_BACKEND=llm for real findings.")


def save_charts(s: dict, out: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed: skipping charts (pip install matplotlib)")
        return
    ink, muted, grid = "#0b0b0b", "#52514e", "#e4e3df"
    colors = {"raw": "#2a78d6", "basic": "#eb6834", "loop": "#1baf7a"}  # reference slots 1-3
    plt.rcParams.update({"font.size": 11, "axes.edgecolor": grid, "axes.labelcolor": muted,
                         "xtick.color": muted, "ytick.color": muted, "text.color": ink})

    # Chart 1: the headline. Overall attacker accuracy per method.
    fig, ax = plt.subplots(figsize=(7, 4))
    vals = [s["attacker_accuracy"][c] * 100 for c in CONDITIONS]
    bars = ax.bar([LABELS[c] for c in CONDITIONS], vals, width=0.5,
                  color=[colors[c] for c in CONDITIONS])
    ax.bar_label(bars, labels=[f"{v:.0f}%" for v in vals], padding=4, color=ink)
    ax.set_ylabel("Attributes the attacker guessed correctly (%)")
    ax.set_ylim(0, 100)
    ax.set_title("How much an attacker AI can still infer", loc="left", fontweight="bold")
    ax.grid(axis="y", color=grid, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    fig.tight_layout()
    fig.savefig(out / "headline.png", dpi=200)
    plt.close(fig)

    # Chart 2: the same, broken down by attribute.
    attrs = [a for a in ATTRIBUTES if s["by_attribute"][a]["raw"] is not None]
    fig, ax = plt.subplots(figsize=(9, 4.2))
    width = 0.26
    for i, c in enumerate(CONDITIONS):
        xs = [j + (i - 1) * (width + 0.02) for j in range(len(attrs))]
        ax.bar(xs, [s["by_attribute"][a][c] * 100 for a in attrs], width=width,
               color=colors[c], label=LABELS[c])
    ax.set_xticks(range(len(attrs)), attrs)
    ax.set_ylabel("Guessed correctly (%)")
    ax.set_ylim(0, 100)
    ax.set_title("Attacker accuracy by attribute", loc="left", fontweight="bold")
    ax.legend(frameon=False, ncols=3, loc="upper left", bbox_to_anchor=(0, -0.12))
    ax.grid(axis="y", color=grid, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    fig.tight_layout()
    fig.savefig(out / "by_attribute.png", dpi=200)
    plt.close(fig)
    print(f"Charts saved to {out}/headline.png and {out}/by_attribute.png")


def attacker_only(records: list[dict]) -> None:
    """For tuning the attacker prompt: a BETTER attacker finds MORE of the true attributes.
    Run on data/dev.jsonl, change one thing in the prompt, run again, keep what scores higher."""
    hits: dict[str, list[bool]] = {a: [] for a in ATTRIBUTES}
    for i, rec in enumerate(records, 1):
        try:
            for a, ok in score(attack(Vault().swap(rec["text"]), config.LOOP_LLM), rec).items():
                hits[a].append(ok)
            print(f"[{i}/{len(records)}] {rec['id']}", flush=True)
        except llm.LLMError as exc:
            print(f"[{i}/{len(records)}] {rec['id']} SKIPPED: {exc}", flush=True)
    print("\nAttacker found (higher = better attacker):")
    for a, h in hits.items():
        if h:
            print(f"  {a:<13} {sum(h) / len(h):>5.0%}  ({sum(h)}/{len(h)})")
    total = [ok for h in hits.values() for ok in h]
    print(f"  {'OVERALL':<13} {sum(total) / max(1, len(total)):>5.0%}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data/test.jsonl")
    ap.add_argument("--limit", type=int, default=None, help="only the first N documents")
    ap.add_argument("--out", default="results")
    ap.add_argument("--attacker-only", action="store_true",
                    help="quick prompt check: how much the LOOP attacker finds on basic-redacted docs")
    args = ap.parse_args()

    records = [json.loads(line) for line in Path(args.data).read_text().splitlines() if line.strip()]
    records = records[:args.limit] if args.limit else records
    if args.attacker_only:
        return attacker_only(records)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    start = time.perf_counter()
    summary, per_doc = run(records, config.BACKEND)
    summary["total_seconds"] = round(time.perf_counter() - start, 1)
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    with (out / "per_doc.jsonl").open("w") as f:
        for row in per_doc:
            f.write(json.dumps(row) + "\n")
    print_summary(summary)
    save_charts(summary, out)


if __name__ == "__main__":
    main()
