"""
Hostile-payload tests for src/security/html_sanitizer.py.

These tests are the regression contract for the body_html XSS class
flagged in the security audit. Each payload represents a real attack
vector that has been used in phishing kits or browser CTFs. The
sanitizer must neutralise all of them BEFORE they reach the dashboard
iframe — even though the iframe is sandboxed (no allow flags), this is
the defense-in-depth layer.

A payload is "neutralised" when:
- script tags / handlers are stripped, AND
- the surviving HTML contains no executable construct, AND
- the literal payload string the attacker chose is not present
  verbatim (proves the parser actually walked it, not just regex-matched)
"""
from __future__ import annotations

import re

import pytest

from src.security.html_sanitizer import (
    sanitize_email_html,
    _sanitize_with_regex,
)


# ─── Empty / type contract ───────────────────────────────────────────────────


class TestEmptyContract:
    def test_none_returns_empty_string(self):
        assert sanitize_email_html(None) == ""

    def test_empty_string_returns_empty(self):
        assert sanitize_email_html("") == ""

    def test_bytes_input_decoded(self):
        # Real emails sometimes hand us bytes from the parser
        result = sanitize_email_html("<p>hello</p>".encode("utf-8"))
        assert "hello" in result

    def test_non_string_non_bytes_returns_empty(self):
        assert sanitize_email_html(12345) == ""  # type: ignore[arg-type]


# ─── Hostile payloads — bleach path (default) ────────────────────────────────


def _assert_no_executable(html: str) -> None:
    """Common assertions for any sanitized output."""
    lower = html.lower()
    # No script tag of any form
    assert "<script" not in lower
    # No event handler attributes
    assert not re.search(r"\son\w+\s*=", lower)
    # No javascript: protocol
    assert "javascript:" not in lower
    # No vbscript: protocol
    assert "vbscript:" not in lower
    # No data: URLs in href/src (data: uri smuggling)
    assert not re.search(r"(href|src)\s*=\s*[\"']?\s*data:", lower)
    # No iframe (the only iframe should be the dashboard's own sandboxed one)
    assert "<iframe" not in lower


class TestScriptTag:
    def test_baseline_script_stripped(self):
        payload = "<p>hello</p><script>alert(1)</script>"
        out = sanitize_email_html(payload)
        _assert_no_executable(out)
        assert "alert(1)" not in out  # contents removed too
        assert "hello" in out  # surrounding content preserved

    def test_script_with_attributes(self):
        payload = '<script type="text/javascript" src="//evil/x.js"></script>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)

    def test_uppercase_script(self):
        out = sanitize_email_html("<SCRIPT>alert(1)</SCRIPT>")
        _assert_no_executable(out)


class TestEventHandlers:
    def test_img_onerror(self):
        payload = '<img src="x" onerror="alert(1)">'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)
        assert "onerror" not in out.lower()

    def test_body_onload(self):
        payload = '<body onload="alert(1)">hello</body>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)

    def test_a_onclick(self):
        payload = '<a href="https://example.com" onclick="alert(1)">x</a>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)
        # The href should survive; only the handler stripped
        assert "https://example.com" in out

    def test_div_onmouseover(self):
        payload = '<div onmouseover="alert(1)">hover</div>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)


class TestSVGNamespaceJS:
    """SVG can carry script via its own namespace."""

    def test_svg_script(self):
        payload = "<svg><script>alert(1)</script></svg>"
        out = sanitize_email_html(payload)
        _assert_no_executable(out)
        assert "<svg" not in out.lower()

    def test_svg_onload(self):
        payload = '<svg onload="alert(1)">'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)

    def test_svg_use_xlink_href_javascript(self):
        # SVG <use xlink:href="javascript:..."> is a real bypass class
        payload = '<svg><use xlink:href="javascript:alert(1)"/></svg>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)


class TestJavaScriptUrlScheme:
    def test_a_href_javascript(self):
        payload = '<a href="javascript:alert(1)">click</a>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)
        # Bleach removes the href entirely; text should still be there
        assert "click" in out

    def test_a_href_javascript_uppercase(self):
        payload = '<a href="JAVASCRIPT:alert(1)">click</a>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)

    def test_a_href_vbscript(self):
        payload = '<a href="vbscript:msgbox(1)">click</a>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)

    def test_iframe_src_javascript(self):
        payload = '<iframe src="javascript:alert(1)"></iframe>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)


class TestDataUri:
    def test_iframe_src_data_html(self):
        payload = '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)

    def test_a_href_data_html(self):
        payload = '<a href="data:text/html,<script>alert(1)</script>">x</a>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)

    def test_object_data_html(self):
        payload = '<object data="data:text/html,<script>alert(1)</script>"></object>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)


class TestMetaRefresh:
    def test_meta_refresh_redirect(self):
        # Meta refresh is a server-side redirect primitive; allow attribute
        # taxonomy must reject it.
        payload = '<meta http-equiv="refresh" content="0;url=https://evil/">'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)
        assert "<meta" not in out.lower()


class TestStyleAndExpressions:
    def test_style_tag_stripped(self):
        payload = "<style>body{background:url('javascript:alert(1)')}</style>hello"
        out = sanitize_email_html(payload)
        _assert_no_executable(out)
        assert "<style" not in out.lower()
        # IE-era expression() vector
        assert "expression(" not in out

    def test_style_attribute_stripped(self):
        # `style` attribute is a CSS injection surface; not in our allowlist
        payload = '<p style="background:url(javascript:alert(1))">hi</p>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)
        assert "style=" not in out.lower()
        assert "hi" in out

    def test_style_import(self):
        payload = '<style>@import url("https://evil/x.css");</style>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)
        assert "@import" not in out


class TestParserQuirks:
    """HTML5 parser edge cases."""

    def test_math_namespace(self):
        payload = '<math><mtext><script>alert(1)</script></mtext></math>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)

    def test_noscript(self):
        payload = '<noscript><img src=x onerror=alert(1)></noscript>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)

    def test_form_with_formaction(self):
        payload = '<form><button formaction="javascript:alert(1)">x</button></form>'
        out = sanitize_email_html(payload)
        _assert_no_executable(out)
        assert "formaction" not in out.lower()

    def test_object_embed(self):
        for tag in ("object", "embed", "applet"):
            payload = f"<{tag} src='evil.swf'></{tag}>"
            out = sanitize_email_html(payload)
            _assert_no_executable(out)
            assert f"<{tag}" not in out.lower()


# ─── Benign content survives ─────────────────────────────────────────────────


class TestBenignContentPreserved:
    def test_paragraph_preserved(self):
        out = sanitize_email_html("<p>Hello <strong>world</strong>!</p>")
        assert "Hello" in out
        assert "<strong>" in out

    def test_legitimate_link_preserved(self):
        out = sanitize_email_html('<a href="https://example.com" title="x">click</a>')
        assert "https://example.com" in out
        assert "click" in out

    def test_image_with_https_src_preserved(self):
        out = sanitize_email_html('<img src="https://cdn.example/logo.png" alt="logo">')
        assert "https://cdn.example/logo.png" in out

    def test_table_preserved(self):
        html = "<table><tr><td>a</td><td>b</td></tr></table>"
        out = sanitize_email_html(html)
        assert "<table>" in out
        assert "<td>" in out
        assert "a" in out and "b" in out


# ─── Regex fallback (bleach unavailable) ─────────────────────────────────────


class TestRegexFallback:
    """
    Direct exercise of _sanitize_with_regex so the fallback path stays
    safe even if it's never reached in CI (bleach is in requirements).
    """

    def test_strips_script_block(self):
        out = _sanitize_with_regex("<p>hi</p><script>alert(1)</script>")
        assert "<script" not in out.lower()
        assert "alert(1)" not in out
        assert "hi" in out

    def test_strips_style_block(self):
        out = _sanitize_with_regex("<style>x{}</style><p>hi</p>")
        assert "<style" not in out.lower()
        assert "hi" in out

    def test_strips_iframe(self):
        out = _sanitize_with_regex('<iframe src="javascript:alert(1)"></iframe>hi')
        assert "<iframe" not in out.lower()
        assert "hi" in out

    def test_strips_event_handlers(self):
        out = _sanitize_with_regex('<p onclick="alert(1)">hi</p>')
        assert "onclick" not in out.lower()
        assert "hi" in out

    def test_strips_meta_self_closing(self):
        out = _sanitize_with_regex('<meta http-equiv="refresh" content="0;url=https://evil/" />')
        assert "<meta" not in out.lower()

    def test_neutralises_javascript_href(self):
        out = _sanitize_with_regex('<a href="javascript:alert(1)">x</a>')
        assert "javascript:" not in out.lower()


# ─── Bleach unavailable → fallback path ──────────────────────────────────────


class TestBleachUnavailableFallback:
    def test_fallback_used_when_bleach_missing(self, monkeypatch):
        """If bleach import raises ImportError, regex fallback runs."""
        from src.security import html_sanitizer

        def boom(html):
            raise ImportError("bleach not installed")

        monkeypatch.setattr(html_sanitizer, "_sanitize_with_bleach", boom)

        out = sanitize_email_html("<p>hi</p><script>alert(1)</script>")
        assert "<script" not in out.lower()
        assert "hi" in out
