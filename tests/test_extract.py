import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.extract import (
    extract_comments,
    extract_forms,
    extract_js_endpoints,
    extract_links,
    extract_loose_fields,
    flags_for_field,
    parse_html,
)

HTML = """
<!doctype html>
<html>
<head>
  <base href="http://box.web/app/">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
  <script>
    fetch('/api/user?id=12');
    axios.get('/download.php?file=report.pdf');
  </script>
</head>
<body>
  <!-- leftover: /backup/admin.bak -->
  <a href="/index.php?page=home">home</a>
  <a href="https://evil.example/cdn.js">cdn</a>
  <form action="upload.php" method="post" enctype="multipart/form-data">
    <input type="file" name="avatar" accept=".png,.php">
    <input type="text" name="title">
    <input type="hidden" name="id" value="3">
    <button type="submit">go</button>
  </form>
  <form action="/search.php" method="get">
    <input type="search" name="q">
  </form>
  <input id="filter" type="text">
</body>
</html>
"""


class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.soup = parse_html(HTML)
        self.page = "http://box.web/app/index.php"

    def test_comments(self):
        comments = extract_comments(self.soup)
        self.assertTrue(any("backup" in c for c in comments))

    def test_links_same_host_only(self):
        inside, outside = extract_links(self.soup, self.page, "box.web")
        self.assertTrue(any("index.php" in u and "page=home" in u for u in inside))
        self.assertTrue(any("evil.example" in u for u in outside))
        self.assertFalse(any("cdnjs.cloudflare.com" in u for u in inside))

    def test_forms_and_flags(self):
        forms = extract_forms(self.soup, self.page)
        self.assertEqual(len(forms), 2)
        upload = next(f for f in forms if "upload" in f.action)
        self.assertTrue(upload.has_file_input)
        names = {f.name: f for f in upload.fields}
        self.assertIn("is_file_input", names["avatar"].flags)
        self.assertIn("is_multipart_form", names["avatar"].flags)
        self.assertIn("is_free_text", names["title"].flags)
        search = next(f for f in forms if "search" in f.action)
        q = search.fields[0]
        self.assertIn("is_search_field", q.flags)

    def test_js_endpoints(self):
        eps = extract_js_endpoints(self.soup, self.page, "box.web")
        self.assertTrue(any("download.php" in e and "file=" in e for e in eps))
        self.assertTrue(any("/api/user" in e or "api/user" in e for e in eps))

    def test_loose_fields(self):
        loose = extract_loose_fields(self.soup)
        self.assertTrue(any(f.name == "filter" for f in loose))

    def test_xml_upload_flags(self):
        flags = flags_for_field(name="doc", field_type="file", accept=".xml,.svg", form_enctype="multipart/form-data")
        self.assertIn("is_file_input", flags)
        self.assertIn("upload_xml_family", flags)
        self.assertIn("accepts_xml", flags)

    def test_login_form_flags(self):
        soup = parse_html(
            """
            <form action="/login.php" method="post" id="loginform">
              <input type="text" name="username">
              <input type="password" name="password">
              <input type="hidden" name="csrf" value="x">
              <input type="checkbox" name="remember">
              <button type="submit">Log in</button>
            </form>
            """
        )
        forms = extract_forms(soup, "http://box.web/login.php")
        self.assertEqual(len(forms), 1)
        by = {f.name: f for f in forms[0].fields}
        self.assertIn("is_login_form", by["username"].flags)
        self.assertIn("is_username_field", by["username"].flags)
        self.assertIn("is_login_form", by["password"].flags)
        self.assertIn("is_password_field", by["password"].flags)
        self.assertIn("is_login_form", by["csrf"].flags)
        self.assertNotIn("is_username_field", by["csrf"].flags)

    def test_register_and_reset_are_login_adjacent(self):
        soup = parse_html(
            """
            <form action="/register.php" method="post" id="registerform">
              <input type="text" name="user_login">
              <input type="email" name="user_email">
              <input type="password" name="password">
              <input type="password" name="password_confirm">
            </form>
            <form action="/lost-password" method="post">
              <input type="email" name="email">
            </form>
            """
        )
        forms = extract_forms(soup, "http://box.web/")
        self.assertEqual(len(forms), 2)
        reg = next(f for f in forms if "register" in f.action)
        reset = next(f for f in forms if "lost" in f.action)
        ru = next(f for f in reg.fields if f.name == "user_login")
        self.assertIn("is_login_adjacent_form", ru.flags)
        self.assertIn("is_username_field", ru.flags)
        self.assertNotIn("is_login_form", ru.flags)
        remail = next(f for f in reset.fields if f.name == "email")
        self.assertIn("is_login_adjacent_form", remail.flags)
        self.assertIn("is_username_field", remail.flags)

    def test_comment_and_newsletter_and_search_placeholder(self):
        soup = parse_html(
            """
            <form id="commentform" action="/wp-comments-post.php" method="post">
              <input type="text" name="author">
              <textarea name="comment"></textarea>
            </form>
            <form action="/newsletter" method="post">
              <input type="email" name="email">
            </form>
            <form action="/x" method="get">
              <input type="text" name="foo" id="search-box" placeholder="Search products">
            </form>
            """
        )
        forms = extract_forms(soup, "http://box.web/")
        comment = next(f for f in forms if any(fld.name == "comment" for fld in f.fields))
        news = next(f for f in forms if "newsletter" in f.action)
        search = next(f for f in forms if any(fld.name == "foo" for fld in f.fields))
        cbody = next(f for f in comment.fields if f.name == "comment")
        self.assertIn("is_comment_form", cbody.flags)
        author = next(f for f in comment.fields if f.name == "author")
        self.assertIn("is_comment_form", author.flags)
        self.assertIn("is_newsletter_form", news.fields[0].flags)
        self.assertIn("is_search_field", search.fields[0].flags)


if __name__ == "__main__":
    unittest.main()
