from __future__ import annotations

import unittest

from assurance import classify, code_mask, original_unconditional_source, remove_action, reset_proofs


THEORY = '''theory Test begin
builtins: signing
rule Accept:
  [ In(<message,key,sig>) ]
  --[ Eq(verify(sig,message,key),true), Accepted(message) ]-> []
lemma honest: exists-trace "Ex message #i. Accepted(message)@i"
by sorry
lemma auth: "All message #i. Accepted(message)@i ==> message = 'ok'"
by sorry
end
'''


class AssuranceTests(unittest.TestCase):
    def test_removal_changes_only_selected_guard(self):
        changed, metadata = remove_action(THEORY, {"rule": "Accept", "predicate": "Eq", "contains_function": "verify"})
        self.assertNotIn("Eq(verify", changed)
        self.assertIn("Accepted(message)", changed)
        self.assertIn("In(<message,key,sig>)", changed)
        self.assertNotEqual(metadata["before_sha256"], metadata["after_sha256"])

    def test_missing_and_ambiguous_action_fail(self):
        selector = {"rule": "Accept", "predicate": "Eq", "contains_function": "verify"}
        with self.assertRaises(ValueError):
            remove_action(THEORY, {**selector, "rule": "Absent"})
        duplicated = THEORY.replace("Eq(verify(sig,message,key),true)", "Eq(verify(sig,message,key),true), Eq(verify(sig,message,key),true)")
        with self.assertRaises(ValueError):
            remove_action(duplicated, selector)

    def test_comment_and_string_mask_preserve_offsets(self):
        source = "// fake rule\n/* outer /* nested */ end */ 'a//b' \"a/*b\""
        masked = code_mask(source)
        self.assertEqual(len(masked), len(source))
        self.assertNotIn("fake rule", masked)
        self.assertIn("'a//b'", masked)
        with self.assertRaises(ValueError):
            code_mask("/* unclosed")

    def test_old_proof_scripts_are_discarded_not_reused(self):
        source = THEORY.replace("by sorry", "simplify\nby contradiction", 1)
        reset = reset_proofs(source)
        self.assertNotIn("by contradiction", reset)
        self.assertEqual(reset.count("by sorry"), 2)
        self.assertIn('"Ex message #i. Accepted(message)@i"', reset)
        self.assertIn("message = 'ok'", reset)

    def test_original_mode_preserves_embedded_guards_and_rejects_proofs(self):
        with self.assertRaisesRegex(ValueError, "proof-free"):
            original_unconditional_source(THEORY, "Accept")
        source = THEORY.replace("by sorry", "").replace("Accepted(message)", "_restrict(message = key), Accepted(message)", 1)
        self.assertEqual(original_unconditional_source(source, "Accept"), source)

    def test_original_mode_rejects_conditional_and_include_dependent_selection(self):
        source = THEORY.replace("by sorry", "")
        conditional = source.replace("rule Accept:", "#ifdef HIDDEN\nrule Accept:").replace("lemma honest:", "#endif\nlemma honest:")
        with self.assertRaisesRegex(ValueError, "conditional"):
            original_unconditional_source(conditional, "Accept")
        with self.assertRaises(ValueError):
            original_unconditional_source('#include "rules.spthy"\n' + source, "Accept")

    def test_quality_outcomes_do_not_credit_blocked_or_incomplete_mutants(self):
        reference = {"passed": True, "actual": {"auth": "verified", "witness": "verified"}}
        def experiment(auth="verified", witness="verified", passed=True):
            return {"passed": passed, "actual": {"auth": auth, "witness": witness}}
        self.assertEqual(classify(reference, experiment(), ["auth"], ["witness"]), "survived")
        self.assertEqual(classify(reference, experiment("falsified"), ["auth"], ["witness"]), "detected")
        self.assertEqual(classify(reference, experiment("falsified", "falsified"), ["auth"], ["witness"]), "execution-blocked")
        self.assertEqual(classify(reference, experiment(passed=False), ["auth"], ["witness"]), "inconclusive")
        self.assertEqual(classify(reference, experiment(), [], ["witness"]), "invalid-policy")


if __name__ == "__main__":
    unittest.main()
