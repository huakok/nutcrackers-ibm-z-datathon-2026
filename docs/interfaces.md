# Interfaces: what each piece hands to the next

If you change one of these, tell the team first: other people's code depends on it.

## 1. Test document (data_gen → evaluate)
One JSON object per line in `data/*.jsonl`:
```json
{
  "id": "s2-0001",
  "doc_type": "hr_email | clinic_note | chat",
  "text": "Hi team, Following up on Rachel Tan's request ...",
  "revealed": ["sex", "age", "region"],
  "profile": {"age": 34, "sex": "female", "region": "west", "occupation": "engineer",
              "education": "postgraduate", "relationship": "married",
              "name": "...", "nric": "...", "phone": "...", "email": "...", "place": "Bukit Batok"}
}
```
`profile` is the **answer key**. Only `evaluate.py` reads it. The attacker and rewriter must never see it, or that's data leakage.

## 2. Attacker output (attacker → rewriter, pipeline, evaluate)
A list of `Guess(attribute, value, confidence, evidence)`. From the AI model, as JSON:
```json
{"guesses": [{"attribute": "age", "value": 34, "confidence": 0.9, "evidence": ["just turned 34"]}]}
```
- `attribute` is one of `age, sex, region, occupation, education, relationship` (`shield/schema.py`).
- `value` is one of the allowed options; age is an integer.
- `evidence` contains **exact** quotes from the text. Invented quotes are dropped.

## 3. Pipeline (anyone → `shield.pipeline.protect`)
```python
result = protect(text, max_rounds=3)
result.redacted   # after basic redaction only
result.text       # final attack-tested text
result.rounds     # list of Round(number, guesses, leaks, text_before, text_after, ...)
result.passed     # True if the attacker found no confident leak at the end
result.vault.restore(answer)   # real values back
```

## 4. HTTP API (frontend → backend)
| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| GET | `/health` | none | `machine` (s390x on LinuxONE), backend, model |
| POST | `/protect` | `{"text", "max_rounds"?}` | `session_id`, `redacted`, `text`, `rounds`, `passed`, `vault_preview` |
| POST | `/restore` | `{"session_id", "text"}` | `{"text"}` with real values |
| POST | `/ask` | `{"session_id", "question"}` | `sent_to_outside_ai`, `answer_with_placeholders`, `answer` |
