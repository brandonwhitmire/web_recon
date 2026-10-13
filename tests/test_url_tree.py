import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.models import FormField, FormRecord, PageRecord
from web_recon.url_tree import LiveUrlTree, format_page_tree, format_url_tree, url_segments


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


class PageTreeTests(unittest.TestCase):
    def test_fields_hang_off_the_page_they_were_parsed_from(self):
        pages = [
            PageRecord(
                url="http://192.168.240.121/?page_id=6",
                final_url="http://192.168.240.121/?page_id=6",
                status=200,
                query_params=[("page_id", "6")],
            ),
            PageRecord(
                url="http://192.168.240.121/login.aspx",
                final_url="http://192.168.240.121/login.aspx",
                status=200,
                forms=[
                    FormRecord(
                        action="http://192.168.240.121/login.aspx",
                        method="POST",
                        enctype="application/x-www-form-urlencoded",
                        fields=[
                            FormField(name="ctl00$ContentPlaceHolder1$UsernameTextBox", field_type="text"),
                            FormField(name="ctl00$ContentPlaceHolder1$PasswordTextBox", field_type="password"),
                            FormField(name="ctl00$ContentPlaceHolder1$LoginButton", field_type="submit"),
                        ],
                    )
                ],
            ),
            PageRecord(
                url="http://192.168.240.121/contact.aspx",
                final_url="http://192.168.240.121/contact.aspx",
                status=200,
                forms=[
                    FormRecord(
                        action="http://192.168.240.121/contact.aspx",
                        method="POST",
                        enctype="application/x-www-form-urlencoded",
                        fields=[
                            FormField(name="message", field_type="textarea"),
                            FormField(name="name", field_type="text"),
                            FormField(name="subject", field_type="text"),
                        ],
                    )
                ],
                loose_fields=[FormField(name="q", field_type="search")],
            ),
        ]
        tree = format_page_tree(pages, "192.168.240.121")
        self.assertEqual(
            tree,
            "\n".join(
                [
                    "192.168.240.121",
                    "├── /",
                    "│   └── ?page_id=6",
                    "│       └── query",
                    "│           └── page_id  query",
                    "├── login.aspx",
                    "│   └── POST /login.aspx",
                    "│       ├── ctl00$ContentPlaceHolder1$UsernameTextBox  text",
                    "│       └── ctl00$ContentPlaceHolder1$PasswordTextBox  password",
                    "└── contact.aspx",
                    "    ├── POST /contact.aspx",
                    "    │   ├── message  textarea",
                    "    │   ├── name  text",
                    "    │   └── subject  text",
                    "    └── loose",
                    "        └── q  search",
                ]
            ),
        )
        self.assertNotIn("LoginButton", tree)


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

    def test_fields_print_under_the_parsed_page(self):
        live = LiveUrlTree("192.168.240.121")
        page = PageRecord(
            url="http://192.168.240.121/contact.aspx",
            final_url="http://192.168.240.121/contact.aspx",
            status=200,
            forms=[
                FormRecord(
                    action="/contact.aspx",
                    method="POST",
                    enctype="",
                    fields=[
                        FormField(name="message", field_type="textarea"),
                        FormField(name="name", field_type="text"),
                    ],
                )
            ],
        )
        lines = live.add_fields(page)
        self.assertEqual(
            lines,
            [
                "├── contact.aspx",
                "│   ├── POST /contact.aspx",
                "│   │   ├── message  textarea",
                "│   │   ├── name  text",
            ],
        )
        self.assertEqual(live.add_fields(page), [])


if __name__ == "__main__":
    unittest.main()
