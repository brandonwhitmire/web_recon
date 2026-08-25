import unittest

from web_recon.term import colorize


class TermColorTests(unittest.TestCase):
    def test_tokens_stripped_when_disabled(self):
        s = colorize("Target: {byellow}10.10.11.12{rst}", enabled=False)
        self.assertEqual(s, "Target: 10.10.11.12")
        self.assertNotIn("\033", s)

    def test_tokens_become_ansi_when_enabled(self):
        s = colorize("{bmagenta}file_inclusion{rst}: {byellow}2{rst}", enabled=True)
        self.assertIn("\033[", s)
        self.assertIn("file_inclusion", s)
        self.assertNotIn("{bmagenta}", s)
        self.assertNotIn("{rst}", s)


if __name__ == "__main__":
    unittest.main()
