import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.url_tree import LiveUrlTree, format_url_tree, url_segments


class UrlSegmentTests(unittest.TestCase):
    def test_root_and_query(self):
        self.assertEqual(url_segments("http://alvida-eatery.local/"), ["/"])
        self.assertEqual(url_segments("http://alvida-eatery.local/?page_id=6"), ["/", "?page_id=6"])

    def test_path_file(self):
        self.assertEqual(url_segments("http://alvida-eatery.local/wp-login.php"), ["wp-login.php"])

    def test_nested_path(self):
        self.assertEqual(url_segments("http://box.web/blog/hello"), ["blog", "hello"])


class FormatTreeTests(unittest.TestCase):
    def test_wordpress_style(self):
        urls = [
            "http://alvida-eatery.local/",
            "http://alvida-eatery.local/?page_id=6",
            "http://alvida-eatery.local/?cat=2",
            "http://alvida-eatery.local/wp-login.php",
        ]
        tree = format_url_tree(urls, "alvida-eatery.local")
        self.assertEqual(
            tree,
            "\n".join(
                [
                    "alvida-eatery.local",
                    "├── /",
                    "│   ├── ?page_id=6",
                    "│   └── ?cat=2",
                    "└── wp-login.php",
                ]
            ),
        )

    def test_nested_dirs(self):
        urls = [
            "http://box.web/",
            "http://box.web/blog/hello",
            "http://box.web/blog/world",
        ]
        tree = format_url_tree(urls, "box.web")
        self.assertIn("├── /", tree)
        self.assertIn("└── blog", tree)
        self.assertIn("├── hello", tree)
        self.assertIn("└── world", tree)


class LiveTreeTests(unittest.TestCase):
    def test_header_once_then_new_nodes(self):
        live = LiveUrlTree("alvida-eatery.local")
        self.assertIn("alvida-eatery.local", live.header_line())
        self.assertIn("crawl", live.header_line())
        self.assertEqual(live.start_lines(), ["alvida-eatery.local"])
        first = live.add("http://alvida-eatery.local/")
        self.assertEqual(first, ["├── /"])
        second = live.add("http://alvida-eatery.local/?cat=2")
        self.assertEqual(second, ["│   ├── ?cat=2"])
        again = live.add("http://alvida-eatery.local/?cat=2")
        self.assertEqual(again, [])


if __name__ == "__main__":
    unittest.main()
