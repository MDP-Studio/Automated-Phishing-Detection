"""
Server-side HTML sanitization for attacker-controlled email bodies.

Defense-in-depth layer behind the sandboxed `<iframe srcdoc>` in
templates/monitor.html. The iframe sandbox (no allow flags) is the actual
security control — it isolates rendered content into an opaque origin so
scripts can't touch the parent document, can't make credentialed network
requests, can't navigate the top frame. This sanitizer adds belt-to-the-
suspenders by stripping the most dangerous constructs *before* the HTML
ever reaches the browser, so even if the sandbox is misconfigured (or a
browser bug bypasses it) the stored content is non-executable.

The two layers are independent on purpose. Read SECURITY.md "Hardening
guidance" for the full rationale and `THREAT_MODEL.md` §6 for which
residual risks remain after this fix.

Implementation strategy:

1. If `bleach` is available, use a strict allowlist:
   - Tags: structural and semantic only (p, div, span, br, h1-h6, a, img,
     ul/ol/li, table tags, blockquote, code, pre, em, strong, b, i, u)
   - Attributes: tightly scoped (no `style`, no `on*`, no `srcdoc`)
   - Protocols: http/https/mailto only — no javascript:, data:, file:,
     vbscript:, gopher:, anything custom
   - Strip (not escape) disallowed tags, so the result remains visually
     close to the original

2. If bleach is not installed for any reason, fall back to a strict
   regex-based strip that removes script/style/iframe/meta/object/embed/
   form/svg blocks entirely and drops on* attributes from anything left.
   Less precise, but still safe.

The sanitizer never raises on input: malformed HTML returns "" rather
than blowing up the upload endpoint.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Bleach-backed sanitizer (preferred) ─────────────────────────────────────

# Tags allowed in rendered email body. Conservative on purpose.
_ALLOWED_TAGS: frozenset[str] = frozenset({
    "a", "abbr", "b", "blockquote", "br", "code", "div", "em", "h1", "h2",
    "h3", "h4", "h5", "h6", "hr", "i", "img", "li", "ol", "p", "pre",
    "small", "span", "strong", "sub", "sup", "table", "tbody", "td", "tfoot",
    "th", "thead", "tr", "u", "ul",
})

# Attribute allowlist. Note: NO `style` (CSS expression() and url() are
# vectors), NO `on*` (event handlers), NO `srcdoc` (iframe injection),
# NO `formaction` (button form override).
_ALLOWED_ATTRIBUTES: dict[str, list[str]] = {
    "a": ["href", "title", "rel"],
    "img": ["src", "alt", "title", "width", "height"],
    "table": ["border", "cellpadding", "cellspacing"],
    "td": ["colspan", "rowspan", "align"],
    "th": ["colspan", "rowspan", "align"],
    "*": ["class", "id", "lang", "dir"],  # generic structural attrs only
}

# URL schemes allowed in href/src. Critically excludes `javascript:`,
# `data:`, `vbscript:`, `file:`, etc.
_ALLOWED_PROTOCOLS: frozenset[str] = frozenset({
    "http", "https", "mailto", "tel",
})


# Bleach with `strip=True` removes the tag wrappers but PRESERVES inner
# text content. That's correct for `<p>` etc. but DANGEROUS for tags
# whose content is itself executable (script, style). So we pre-strip
# the entire `<script>...</script>` / `<style>...</style>` block before
# handing the rest to bleach.
_PRE_STRIP_BLOCK_PATTERN = re.compile(
    r"<(script|style)\b[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)


def _sanitize_with_bleach(html: str) -> str:
    """
    Use bleach.clean with our strict allowlist.

    Pre-step: drop `<script>...</script>` and `<style>...</style>` blocks
    entirely (tags AND their content). bleach by itself would only strip
    the wrappers and leave the executable text behind.
    """
    import bleach  # local import — module is optional

    pre_stripped = _PRE_STRIP_BLOCK_PATTERN.sub("", html)
    return bleach.clean(
        pre_stripped,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        protocols=_ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )


# ─── Regex fallback (used only if bleach is unavailable) ─────────────────────

# Block tags whose entire contents must be removed, not just the tags.
_BLOCK_TAGS = (
    "script", "style", "iframe", "object", "embed", "form", "svg",
    "math", "noscript", "frame", "frameset", "applet", "meta", "link",
    "base", "audio", "video", "source", "track",
)

# One regex per block tag to strip the whole `<tag ...>...</tag>` span,
# DOTALL because the body can span lines.
_BLOCK_TAG_PATTERNS = [
    re.compile(rf"<{t}\b[^>]*>.*?</{t}\s*>", re.IGNORECASE | re.DOTALL)
    for t in _BLOCK_TAGS
]
# And a self-closing variant for tags like <meta ... /> or <link ... />
_SELF_CLOSING_BLOCK_PATTERNS = [
    re.compile(rf"<{t}\b[^>]*/?>", re.IGNORECASE)
    for t in _BLOCK_TAGS
]

# Strip on* event handler attributes from any remaining tag.
# `onclick="..."`, `onerror=...`, `ONLOAD = '...'`, etc.
_EVENT_HANDLER_PATTERN = re.compile(
    r"\son\w+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)",
    re.IGNORECASE,
)

# Strip dangerous-protocol URLs in href/src.
_DANGEROUS_PROTOCOL_PATTERN = re.compile(
    r"\b(href|src|action|formaction|background|cite|longdesc|usemap|profile|"
    r"icon|manifest|poster|srcset|data)\s*=\s*(?:\"|')?\s*"
    r"(?:javascript|vbscript|data|file|about):",
    re.IGNORECASE,
)


def _sanitize_with_regex(html: str) -> str:
    """
    Last-resort sanitizer used only when bleach is unavailable.

    Removes block-level dangerous tags entirely (script, style, iframe,
    object, embed, form, svg, math, noscript, meta, link, etc.), then
    strips event-handler attributes and dangerous URL schemes from
    anything that survived.

    Less semantic than the bleach path but never executes attacker code.
    """
    out = html
    for pattern in _BLOCK_TAG_PATTERNS:
        out = pattern.sub("", out)
    for pattern in _SELF_CLOSING_BLOCK_PATTERNS:
        out = pattern.sub("", out)
    out = _EVENT_HANDLER_PATTERN.sub("", out)
    # For dangerous protocols, neutralise the attribute by deleting it
    out = _DANGEROUS_PROTOCOL_PATTERN.sub('href="#"', out)
    return out


# ─── Public entry point ──────────────────────────────────────────────────────


def sanitize_email_html(html: Optional[str]) -> str:
    """
    Sanitize an attacker-controlled email body HTML for safe rendering
    inside a sandboxed iframe.

    This is defense-in-depth — the actual security boundary is the
    `<iframe sandbox srcdoc="...">` with no allow flags in the dashboard
    template. This function makes the stored value non-executable so that
    if the sandbox is ever bypassed or misconfigured, the content is
    still safe.

    Args:
        html: Raw HTML body from an email. May be None or empty.

    Returns:
        Sanitized HTML string. Empty string for None / empty input or
        on any internal failure (fail-closed).
    """
    if not html:
        return ""

    if not isinstance(html, str):
        try:
            html = html.decode("utf-8", errors="replace")
        except Exception:
            return ""

    try:
        return _sanitize_with_bleach(html)
    except ImportError:
        logger.warning(
            "bleach not installed — falling back to regex sanitizer for body_html. "
            "Install with: pip install bleach"
        )
        try:
            return _sanitize_with_regex(html)
        except Exception:
            logger.exception("Regex HTML sanitizer failed; returning empty string")
            return ""
    except Exception:
        # Any sanitizer failure must produce safe-by-default empty output.
        logger.exception("HTML sanitizer failed; returning empty string")
        return ""
