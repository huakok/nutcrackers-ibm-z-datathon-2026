"""Run with:  python3 -m unittest discover tests   (standard library only, works on LinuxONE too)"""
import json
import unittest
from unittest import mock

from shield import attacker, llm, rewriter
from shield.attacker import Guess, heuristic_attack, llm_attack
from shield.config import LLMSettings
from shield.data_gen import generate
from shield.detector import detect, is_valid_nric, nric_check_letter
from shield.pipeline import protect
from shield.scoring import is_correct, score
from shield.vault import Vault

SAMPLE = ("Hi team, following up on Ms Rachel Tan's leave (NRIC S1234567D). She just turned 34 "
          "and lives in Bukit Batok. Rachel is a staff nurse. Call +65 9123 4567 or rachel@example.com.")


class TestDetector(unittest.TestCase):
    def test_nric_check_letter(self):
        self.assertEqual(nric_check_letter("S", "1234567"), "D")
        self.assertTrue(is_valid_nric("S1234567D"))
        self.assertFalse(is_valid_nric("S1234567A"))      # wrong check letter

    def test_finds_direct_identifiers(self):
        kinds = {e.kind for e in detect(SAMPLE)}
        self.assertTrue({"PERSON", "NRIC", "PHONE", "EMAIL"} <= kinds)

    def test_bank_accounts(self):
        for text in ["DBS account 123-45678-9", "OCBC a/c no: 501-234567-001",
                     "UOB 123-456-789-0", "POSB savings account number 1234567890",
                     "IBAN GB29 NWBK 6016 1331 9268 19"]:
            self.assertIn("BANK", {e.kind for e in detect(text)}, text)

    def test_numbers_without_bank_context_are_left_alone(self):
        self.assertFalse(detect("Invoice 1234567890 is overdue. Order placed 2026-10-17."))

    def test_place_names_are_not_people(self):
        self.assertFalse([e for e in detect("She lives in Bukit Batok.") if e.kind == "PERSON"])
        self.assertFalse([e for e in detect("They live in Ang Mo Kio now.") if e.kind == "PERSON"])
        self.assertTrue([e for e in detect("Ask Marcus Ang about it.") if e.kind == "PERSON"])

    def test_generated_documents_lose_all_direct_identifiers(self):
        for rec in generate(30, seed=7):
            p, text = rec["profile"], Vault().swap(rec["text"])
            account_digits = p["bank"].split()[-1]
            for value in (p["nric"], p["phone"], p["email"], p["first_name"], account_digits):
                self.assertNotIn(value, text, f"{value} leaked in {rec['id']}")


class TestVault(unittest.TestCase):
    def test_consistent_placeholders_and_restore(self):
        v = Vault()
        text = v.swap(SAMPLE)
        self.assertNotIn("Rachel", text)
        self.assertEqual(text.count("[PERSON_1]"), 2)        # full name and later "Rachel"
        self.assertIn("Rachel Tan", v.restore("Tell [PERSON_1] to rest."))

    def test_values_are_encrypted_at_rest(self):
        v = Vault()
        v.swap(SAMPLE)
        if v.encrypted:
            self.assertNotIn(b"Rachel", b"".join(v._store.values()))


class TestAttackLoop(unittest.TestCase):
    def test_heuristic_attacker_finds_clues(self):
        found = {g.attribute: g.value for g in heuristic_attack(Vault().swap(SAMPLE))}
        self.assertEqual(found["age"], 34)
        self.assertEqual(found["region"], "west")
        self.assertEqual(found["occupation"], "healthcare")

    def test_loop_removes_leaks_and_keeps_placeholders(self):
        result = protect(SAMPLE, backend="heuristic")
        self.assertTrue(result.passed)
        self.assertIn("[PERSON_1]", result.text)
        self.assertNotIn("Bukit Batok", result.text)

    def test_broken_attacker_reply_means_not_cleared(self):
        with mock.patch.object(llm, "chat", return_value=('{"guesses": [{"attribute": "age" "value": 3}]}', 0.1)):
            result = protect(SAMPLE, backend="llm")
        self.assertFalse(result.passed)
        self.assertIn("unusable", result.error)

    def test_unsafe_ai_rewrite_is_rejected(self):
        before = "[PERSON_1] lives in Bukit Batok."
        self.assertFalse(rewriter.is_safe_rewrite(before, "Someone lives in Singapore."))
        self.assertFalse(rewriter.is_safe_rewrite(before, "[PERSON_1] (S1234567D) lives here."))
        self.assertTrue(rewriter.is_safe_rewrite(before, "[PERSON_1] lives in Singapore."))


class TestLLMParsing(unittest.TestCase):
    """The real attacker, with the model call faked, so this runs with no model installed."""

    def test_llm_attacker_parses_and_filters(self):
        reply = 'Sure! ```json\n' + json.dumps({"guesses": [
            {"attribute": "age", "value": 34, "confidence": 0.9, "evidence": ["just turned 34"]},
            {"attribute": "region", "value": "West", "confidence": 0.8, "evidence": ["Bukit Batok", "made up"]},
            {"attribute": "occupation", "value": "astronaut", "confidence": 0.9, "evidence": []},
        ]}) + "\n```"
        with mock.patch.object(llm, "chat", return_value=(reply, 0.1)):
            guesses = llm_attack("She just turned 34 and lives in Bukit Batok.", LLMSettings("x", "m"))
        by_attr = {g.attribute: g for g in guesses}
        self.assertEqual(by_attr["region"].value, "west")
        self.assertEqual(by_attr["region"].evidence, ["Bukit Batok"])   # invented quote dropped
        self.assertNotIn("occupation", by_attr)                          # invalid option dropped


    def test_guess_without_evidence_is_not_a_leak(self):
        self.assertFalse(attacker.is_leak(Guess("age", 30, 1.0, [])))
        self.assertTrue(attacker.is_leak(Guess("age", 30, 1.0, ["turned 30"])))

    def test_models_are_asked_for_a_fixed_json_shape(self):
        reply = json.dumps({"guesses": []})
        with mock.patch.object(llm, "chat", return_value=(reply, 0.1)) as chat:
            llm_attack("text", LLMSettings("x", "m"))
        self.assertIs(chat.call_args.kwargs["schema"], attacker.ATTACKER_SCHEMA)

    def test_compact_reply_format(self):
        reply = json.dumps({"age": {"v": 34, "e": "just turned 34"},
                            "region": {"v": "west", "e": "Bukit Batok"}})
        with mock.patch.object(llm, "chat", return_value=(reply, 0.1)):
            guesses = {g.attribute: g for g in llm_attack("She just turned 34 in Bukit Batok.",
                                                          LLMSettings("x", "m"))}
        self.assertEqual(guesses["age"].value, 34)
        self.assertEqual(guesses["region"].evidence, ["Bukit Batok"])

    def test_several_quotes_per_attribute_all_get_suppressed(self):
        text = "He is a site engineer on the Tuas plant retrofit."
        reply = json.dumps({"occupation": {"v": "engineer", "e": ["site engineer", "Tuas plant retrofit"]}})
        with mock.patch.object(llm, "chat", return_value=(reply, 0.1)):
            g = llm_attack(text, LLMSettings("x", "m"))[0]
        self.assertEqual(g.evidence, ["site engineer", "Tuas plant retrofit"])
        self.assertEqual(rewriter.suppress_rewrite(text, [g]), "He is a [JOB] on the [JOB].")

    def test_quotes_match_whole_words_only(self):
        reply = json.dumps({"occupation": {"v": "manager", "e": ["he", "manager"]}})
        text = "Then the operations manager left."
        with mock.patch.object(llm, "chat", return_value=(reply, 0.1)):
            g = llm_attack(text, LLMSettings("x", "m"))[0]
        self.assertEqual(g.evidence, ["manager"])                     # "he" only occurs inside words
        self.assertEqual(rewriter.suppress_rewrite("Then the art start.", [Guess("occupation", "it", 1.0, ["art"])]),
                         "Then the [JOB] start.")

    def test_schema_restricts_values(self):
        props = attacker.ATTACKER_SCHEMA["properties"]
        self.assertEqual(props["region"]["properties"]["v"]["enum"], ["north", "north-east", "east", "west", "central"])
        self.assertEqual(props["age"]["properties"]["v"]["type"], "integer")

    def test_guess_without_confidence_still_counts(self):
        reply = json.dumps({"guesses": [{"attribute": "age", "value": "45", "evidence": "turned 45"}]})
        with mock.patch.object(llm, "chat", return_value=(reply, 0.1)):
            g = llm_attack("He just turned 45.", LLMSettings("x", "m"))[0]
        self.assertEqual(g.value, 45)
        self.assertTrue(attacker.is_leak(g))

    def test_stale_evidence_is_ignored(self):
        self.assertTrue(attacker.is_stale("They their family"))
        self.assertTrue(attacker.is_stale("in Singapore"))
        self.assertFalse(attacker.is_stale("lives in Choa Chu Kang"))
        self.assertFalse(attacker.is_stale("left school"))      # a real hint when no label is present

    def test_rule_fallback_never_deletes_placeholders_or_sentences(self):
        text = "Address: [ADDRESS_1], [UNIT_1]. They take the bus in every single morning to work early."
        leaks = [Guess("region", "central", 1.0, ["Address: [ADDRESS_1], [UNIT_1]",
                                                   "take the bus in every single morning to work early"])]
        self.assertEqual(rewriter.heuristic_rewrite(text, leaks), text)

    def test_evidence_given_as_one_string(self):
        reply = json.dumps({"guesses": [{"attribute": "age", "value": 35, "confidence": 1.0,
                                         "evidence": "just turned 35"}]})
        with mock.patch.object(llm, "chat", return_value=(reply, 0.1)):
            g = llm_attack("He just turned 35 last month.", LLMSettings("x", "m"))[0]
        self.assertEqual(g.evidence, ["just turned 35"])

    def test_sex_guess_gets_pronoun_evidence(self):
        reply = json.dumps({"guesses": [{"attribute": "sex", "value": "male", "confidence": 1.0, "evidence": []}]})
        with mock.patch.object(llm, "chat", return_value=(reply, 0.1)):
            g = llm_attack("He said his wife is away.", LLMSettings("x", "m"))[0]
        self.assertEqual(set(g.evidence), {"He", "his", "wife"})

    def test_llm_rewrite_replaces_the_attackers_quotes(self):
        text = "[PERSON_1] lives in Bukit Batok and he is a staff nurse since he turned 35."
        leaks = [Guess("region", "west", 1.0, ["lives in Bukit Batok"]),
                 Guess("occupation", "healthcare", 1.0, ["a staff nurse"]),
                 Guess("age", 35, 1.0, ["since he turned 35"]),
                 Guess("sex", "male", 1.0, ["he"])]
        reply = json.dumps({"replacements": ["lives in Singapore",
                                             "[PERSON_2] works",          # refused: placeholder
                                             "for some years"]})
        with mock.patch.object(llm, "chat", return_value=(reply, 0.1)) as chat:
            out = rewriter.llm_rewrite(text, leaks, LLMSettings("x", "m"))
        # Quotes containing "he" still matched, because pronouns are swapped last.
        self.assertEqual(out, "[PERSON_1] lives in Singapore and they are a staff nurse for some years.")
        self.assertEqual(chat.call_args.kwargs["schema"]["properties"]["replacements"]["minItems"], 3)

    def test_default_suppresses_with_labels_and_no_model_call(self):
        leaks = [Guess("age", 45, 1.0, ["just turned 45"]), Guess("region", "west", 1.0, ["Choa Chu Kang"]),
                 Guess("sex", "male", 1.0, ["He"])]
        with mock.patch.object(llm, "chat") as chat:
            out, used_ai = rewriter.rewrite("He just turned 45 and lives in Choa Chu Kang.", leaks, backend="llm")
        chat.assert_not_called()
        self.assertFalse(used_ai)
        self.assertEqual(out, "They [AGE] and lives in [LOCATION].")

    def test_labels_are_not_evidence(self):
        self.assertTrue(attacker.is_stale("lives in [LOCATION]"))
        self.assertTrue(attacker.is_stale("They [AGE]"))
        self.assertTrue(attacker.is_stale("He [AGE]"))
        self.assertTrue(attacker.is_stale("Please contact [PERSON_1] at [PHONE_1]"))

    def test_suppression_keeps_words_around_labels_and_merges_repeats(self):
        leaks = [Guess("occupation", "engineer", 1.0, ["site engineer", "He [JOB]", "plant retrofit"])]
        out = rewriter.suppress_rewrite("He [JOB] is a site engineer plant retrofit.", leaks)
        self.assertEqual(out, "He [JOB] is a [JOB].")

    def test_gender_is_neutralised_even_if_attacker_never_flags_it(self):
        with mock.patch.object(llm, "chat", return_value=(json.dumps({}), 0.1)):
            result = protect("Ms Rachel Tan is a nurse. She lives near her husband's office.", backend="llm")
        self.assertEqual(result.text, "[PERSON_1] is a nurse. They live near their partner's office.")

    def test_consistency_rule_ignores_flipped_guesses(self):
        # Round 1: a real clue. Round 2: the attacker "finds" a different age in harmless text.
        replies = [
            json.dumps({"age": {"v": 45, "e": "just turned 45"}}),
            json.dumps({"age": {"v": 30, "e": "takes the bus"}}),
        ]
        with mock.patch.object(llm, "chat", side_effect=[(r, 0.1) for r in replies]):
            result = protect("He just turned 45 and takes the bus.", backend="llm", max_rounds=3)
        self.assertTrue(result.passed)
        self.assertEqual(len(result.rounds), 2)
        self.assertIn("takes the bus", result.text)       # harmless phrase kept
        self.assertNotIn("45", result.text)               # real clue removed

    def test_ai_mode_falls_back_to_labels_on_unusable_reply(self):
        leaks = [Guess("region", "west", 1.0, ["Bukit Batok"])]
        with mock.patch.object(rewriter.config, "REWRITE_MODE", "ai"), \
             mock.patch.object(llm, "chat", return_value=("I cannot help with that.", 0.1)):
            out, used_ai = rewriter.rewrite("[PERSON_1] lives in Bukit Batok.", leaks,
                                            LLMSettings("x", "m"), backend="llm")
        self.assertFalse(used_ai)
        self.assertEqual(out, "[PERSON_1] lives in [LOCATION].")

    def test_copied_list_numbers_are_stripped(self):
        out, n = rewriter.apply_replacements("They lives in Choa Chu Kang.", ["lives in Choa Chu Kang"],
                                             ["2. Lives in Singapore"])
        self.assertEqual(out, "They lives in Singapore.")


class TestScoring(unittest.TestCase):
    def test_age_tolerance(self):
        self.assertTrue(is_correct("age", 38, 34))
        self.assertFalse(is_correct("age", 45, 34))

    def test_only_revealed_attributes_are_scored(self):
        rec = {"revealed": ["sex", "age"], "profile": {"sex": "female", "age": 34}}
        self.assertEqual(score([Guess("sex", "female", 0.9)], rec), {"sex": True, "age": False})


if __name__ == "__main__":
    unittest.main()
