import unittest

from app import valid_account


class AccountIdValidationTests(unittest.TestCase):
    def test_named_account_parts_and_separators(self):
        for value in ("alice.near", "max_99.near", "a.bro", "contract-2.near"):
            with self.subTest(value=value):
                self.assertTrue(valid_account(value))

    def test_implicit_near_and_evm_derived_near_ids(self):
        for value in ("a" * 64, "0x" + "a" * 40, "0s" + "b" * 40):
            with self.subTest(value=value):
                self.assertTrue(valid_account(value))

    def test_rejects_invalid_length_case_and_parts(self):
        for value in ("a", "", "Alice.near", "a..near", "-alice.near", "alice-.near", "alice.near-"):
            with self.subTest(value=value):
                self.assertFalse(valid_account(value))


if __name__ == "__main__":
    unittest.main()
