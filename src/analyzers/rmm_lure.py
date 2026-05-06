"""Detect remote monitoring and management lure patterns in email."""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import unquote, urlparse

from src.models import AnalyzerResult, AttachmentObject, EmailObject, ExtractedURL
from src.utils.domains import get_root_domain


class RMMLureAnalyzer:
    """Detect lures that try to make users install remote access tools."""

    ANALYZER_NAME = "rmm_lure"

    LURE_CATEGORIES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
        (
            "ssa_statement",
            "Fake SSA or benefits statement",
            (
                "social security",
                "ssa",
                "benefit statement",
                "benefits statement",
                "my social security",
            ),
        ),
        (
            "invoice_or_statement",
            "Invoice or account statement",
            (
                "invoice",
                "statement",
                "receipt",
                "remittance",
                "purchase order",
                "account statement",
            ),
        ),
        (
            "collaboration_update",
            "Teams, Zoom, or collaboration update",
            (
                "microsoft teams",
                "teams update",
                "zoom update",
                "zoom meeting",
                "meeting update",
                "video meeting",
            ),
        ),
        (
            "adobe_update",
            "Adobe or document viewer update",
            (
                "adobe",
                "acrobat",
                "pdf viewer",
                "reader update",
                "document cloud",
            ),
        ),
        (
            "hr_document",
            "HR, payroll, or employee document",
            (
                "human resources",
                "hr document",
                "payroll",
                "employee handbook",
                "performance review",
                "benefits update",
            ),
        ),
        (
            "tax_document",
            "Tax document or refund notice",
            (
                "tax document",
                "tax return",
                "tax refund",
                "irs",
                "ato",
                "1099",
                "w-2",
                "bas statement",
                "gst statement",
            ),
        ),
        (
            "crypto_account_warning",
            "Crypto account warning",
            (
                "crypto account",
                "wallet warning",
                "seed phrase",
                "withdrawal alert",
                "coinbase",
                "binance",
                "metamask",
            ),
        ),
        (
            "shared_document",
            "Shared or protected document",
            (
                "shared document",
                "secure document",
                "protected document",
                "view document",
                "document portal",
                "online document",
            ),
        ),
    )

    REMOTE_ACCESS_KEYWORDS: dict[str, tuple[str, ...]] = {
        "AnyDesk": ("anydesk",),
        "TeamViewer": ("teamviewer", "team viewer", "quick support", "quicksupport"),
        "ConnectWise ScreenConnect": (
            "screenconnect",
            "connectwise",
            "control client",
        ),
        "Splashtop": ("splashtop",),
        "LogMeIn": ("logmein", "log me in", "gotoassist", "gotomypc"),
        "BeyondTrust": ("bomgar", "beyondtrust"),
        "RustDesk": ("rustdesk",),
        "UltraViewer": ("ultraviewer", "ultra viewer"),
        "DWService": ("dwservice", "dw agent"),
        "Zoho Assist": ("zoho assist",),
        "Radmin": ("radmin",),
        "Ammyy Admin": ("ammyy",),
        "AeroAdmin": ("aeroadmin",),
        "Remote Utilities": ("remote utilities",),
        "VNC": ("realvnc", "tightvnc", "vnc viewer"),
        "Chrome Remote Desktop": ("chrome remote desktop",),
        "Quick Assist": ("quick assist", "quickassist"),
        "MeshCentral": ("meshcentral",),
        "Atera": ("atera agent", "atera"),
        "NinjaOne": ("ninjaone", "ninja agent"),
        "Tactical RMM": ("tactical rmm",),
        "Supremo": ("supremo",),
    }

    DOWNLOAD_PROMPT_PATTERNS: tuple[str, ...] = (
        r"\bdownload\s+(?:the\s+)?(?:document|viewer|installer|update|secure\s+viewer|file)\b",
        r"\bclick\s+(?:here\s+)?to\s+download\b",
        r"\bdownload\s+and\s+(?:run|open|install)\b",
        r"\brun\s+(?:the\s+)?(?:installer|setup|viewer|update)\b",
        r"\bopen\s+(?:the\s+)?(?:secure\s+viewer|downloaded\s+file|installer)\b",
        r"\binstall\s+(?:the\s+)?(?:viewer|update|support\s+tool|client|plugin)\b",
        r"\brequired\s+(?:viewer|update|plugin|installer)\b",
    )

    INSTALLER_LANGUAGE_PATTERNS: tuple[str, ...] = (
        r"\bsetup(?:\.exe| file)?\b",
        r"\bwindows\s+installer\b",
        r"\bmsi\s+package\b",
        r"\bremote\s+(?:support|session|access|assistance)\b",
        r"\bsupport\s+(?:agent|client|session|tool)\b",
        r"\ballow\s+(?:remote\s+)?(?:access|control)\b",
        r"\bgrant\s+(?:remote\s+)?(?:access|control)\b",
        r"\bconnect\s+to\s+(?:this\s+)?device\b",
    )

    FAKE_DOCUMENT_FLOW_PATTERNS: tuple[str, ...] = (
        r"\b(?:view|open|review|download)\s+(?:the\s+)?(?:secure|protected|shared)?\s*document\b",
        r"\b(?:document|statement|invoice)\s+(?:viewer|portal)\b",
        r"\bfile\s+preview\s+(?:is\s+)?unavailable\b",
        r"\bpreview\s+(?:requires|needs)\s+(?:an\s+)?update\b",
    )

    DANGEROUS_DOWNLOAD_EXTENSIONS = (
        ".exe",
        ".msi",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".hta",
        ".lnk",
    )
    SUSPICIOUS_CONTAINER_EXTENSIONS = (".zip", ".iso", ".img", ".rar", ".7z")
    FILENAME_RE = re.compile(
        r"(?<![\w.-])([\w][\w ._()%-]{0,90}\."
        r"(?:exe|msi|scr|bat|cmd|ps1|vbs|js|hta|lnk|zip|iso|img|rar|7z))\b",
        re.IGNORECASE,
    )

    async def analyze(
        self,
        email: EmailObject,
        iocs: dict | None = None,
        extracted_urls: list[ExtractedURL] | None = None,
    ) -> AnalyzerResult:
        """Analyze email content for RMM or remote-access installation lures."""
        del iocs
        extracted_urls = extracted_urls or []
        text = self._combined_text(email)
        urls = self._all_urls(extracted_urls)
        domains = self._linked_domains(urls)
        file_names = self._file_names(email.attachments, text, urls)
        dangerous_files = [
            name for name in file_names
            if self._extension(name) in self.DANGEROUS_DOWNLOAD_EXTENSIONS
        ]
        container_files = [
            name for name in file_names
            if self._extension(name) in self.SUSPICIOUS_CONTAINER_EXTENSIONS
        ]
        category_id, category_label = self._lure_category(text, file_names)
        remote_tools = self._remote_tool_mentions(text)
        download_prompts = self._matched_patterns(text, self.DOWNLOAD_PROMPT_PATTERNS)
        installer_language = self._matched_patterns(text, self.INSTALLER_LANGUAGE_PATTERNS)
        fake_document_markers = self._matched_patterns(text, self.FAKE_DOCUMENT_FLOW_PATTERNS)
        suspicious_download_indicators = self._download_indicators(
            dangerous_files=dangerous_files,
            container_files=container_files,
            download_prompts=download_prompts,
            installer_language=installer_language,
            urls=urls,
        )
        risky_flow = bool(
            domains
            and (
                suspicious_download_indicators
                or dangerous_files
                or installer_language
            )
            and (
                remote_tools
                or fake_document_markers
                or category_id != "unknown"
            )
        )

        if not any((
            category_id != "unknown",
            remote_tools,
            suspicious_download_indicators,
            installer_language,
            fake_document_markers,
        )):
            return AnalyzerResult(
                analyzer_name=self.ANALYZER_NAME,
                risk_score=0.0,
                confidence=0.0,
                details={
                    "message": "no_rmm_lure_indicators",
                    "summary": "No remote access installation lure indicators were found.",
                },
                status="skipped",
            )

        risk_score = self._risk_score(
            category_id=category_id,
            remote_tools=remote_tools,
            download_prompts=download_prompts,
            installer_language=installer_language,
            dangerous_files=dangerous_files,
            container_files=container_files,
            domains=domains,
            fake_document_markers=fake_document_markers,
            risky_flow=risky_flow,
        )
        confidence = self._confidence(
            category_id=category_id,
            remote_tools=remote_tools,
            suspicious_download_indicators=suspicious_download_indicators,
            installer_language=installer_language,
            domains=domains,
            risky_flow=risky_flow,
        )
        summary = self._summary(risk_score, risky_flow, remote_tools)
        guidance = [
            "Do not run any installer or support tool from this email.",
            "Report the email through your normal security channel.",
            "If the installer was already opened, disconnect or isolate the device and escalate immediately.",
        ]
        details = {
            "summary": summary,
            "risk_score": risk_score,
            "lure_category": {
                "id": category_id,
                "label": category_label,
            },
            "detected_remote_tool_keywords": remote_tools,
            "suspicious_download_indicators": suspicious_download_indicators,
            "linked_domains": domains,
            "file_names": file_names,
            "download_prompts": download_prompts,
            "installer_language": installer_language,
            "fake_document_flow_indicators": fake_document_markers,
            "risky_flow": risky_flow,
            "flow": self._flow(domains, fake_document_markers, dangerous_files, installer_language),
            "user_guidance": guidance,
        }
        return AnalyzerResult(
            analyzer_name=self.ANALYZER_NAME,
            risk_score=risk_score,
            confidence=confidence,
            details=details,
            evidence=self._evidence(details),
        )

    def _combined_text(self, email: EmailObject) -> str:
        html_text = re.sub(r"<[^>]+>", " ", email.body_html or "")
        return unescape(
            " ".join([
                email.subject or "",
                email.from_display_name or "",
                email.from_address or "",
                email.reply_to or "",
                email.body_plain or "",
                html_text,
            ])
        ).lower()

    def _all_urls(self, extracted_urls: list[ExtractedURL]) -> list[str]:
        urls: list[str] = []
        for item in extracted_urls:
            for candidate in [item.url, item.resolved_url, *(item.redirect_chain or [])]:
                if candidate and candidate not in urls:
                    urls.append(candidate)
        return urls[:25]

    def _linked_domains(self, urls: list[str]) -> list[str]:
        domains: list[str] = []
        for url in urls:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().strip(".")
            if not host:
                continue
            root = get_root_domain(host)
            if root and root not in domains:
                domains.append(root)
        return domains[:10]

    def _file_names(
        self,
        attachments: list[AttachmentObject],
        text: str,
        urls: list[str],
    ) -> list[str]:
        names: list[str] = []
        for attachment in attachments or []:
            if attachment.filename:
                names.append(attachment.filename.strip())

        for match in self.FILENAME_RE.findall(text):
            names.append(match.strip(" ."))

        for url in urls:
            parsed = urlparse(url)
            path_name = unquote(parsed.path.rsplit("/", 1)[-1])
            if path_name and self._extension(path_name):
                names.append(path_name.strip(" ."))
            query_names = self.FILENAME_RE.findall(unquote(parsed.query or ""))
            names.extend(name.strip(" .") for name in query_names)

        deduped: list[str] = []
        for name in names:
            lowered = name.lower()
            if lowered and lowered not in {item.lower() for item in deduped}:
                deduped.append(name)
        return deduped[:20]

    def _lure_category(self, text: str, file_names: list[str]) -> tuple[str, str]:
        corpus = " ".join([text, " ".join(file_names).lower()])
        for category_id, label, terms in self.LURE_CATEGORIES:
            if any(term in corpus for term in terms):
                return category_id, label
        return "unknown", "Unknown remote-access lure"

    def _remote_tool_mentions(self, text: str) -> list[str]:
        mentions: list[str] = []
        for label, terms in self.REMOTE_ACCESS_KEYWORDS.items():
            if any(term in text for term in terms):
                mentions.append(label)
        return mentions[:10]

    def _matched_patterns(self, text: str, patterns: tuple[str, ...]) -> list[str]:
        matches: list[str] = []
        for pattern in patterns:
            found = re.search(pattern, text, flags=re.IGNORECASE)
            if found:
                cleaned = re.sub(r"\s+", " ", found.group(0)).strip()
                if cleaned and cleaned not in matches:
                    matches.append(cleaned)
        return matches[:8]

    def _download_indicators(
        self,
        *,
        dangerous_files: list[str],
        container_files: list[str],
        download_prompts: list[str],
        installer_language: list[str],
        urls: list[str],
    ) -> list[str]:
        indicators: list[str] = []
        for name in dangerous_files[:5]:
            indicators.append(f"Executable-style download referenced: {name}")
        for name in container_files[:3]:
            indicators.append(f"Archive or disk-image download referenced: {name}")
        for prompt in download_prompts[:4]:
            indicators.append(f"Download prompt found: {prompt}")
        for phrase in installer_language[:4]:
            indicators.append(f"Installer or remote-support language found: {phrase}")
        if any(self._extension(urlparse(url).path) in self.DANGEROUS_DOWNLOAD_EXTENSIONS for url in urls):
            indicators.append("A linked URL path appears to point directly to an installer.")
        return indicators[:10]

    def _risk_score(
        self,
        *,
        category_id: str,
        remote_tools: list[str],
        download_prompts: list[str],
        installer_language: list[str],
        dangerous_files: list[str],
        container_files: list[str],
        domains: list[str],
        fake_document_markers: list[str],
        risky_flow: bool,
    ) -> float:
        risk = 0.0
        if category_id != "unknown":
            risk += 0.12
        if domains:
            risk += 0.05
        if remote_tools:
            risk += 0.35
        if download_prompts:
            risk += 0.16
        if installer_language:
            risk += 0.18
        if dangerous_files:
            risk += 0.25
        elif container_files:
            risk += 0.12
        if fake_document_markers:
            risk += 0.10
        if risky_flow:
            risk += 0.15
        return round(min(risk, 1.0), 4)

    def _confidence(
        self,
        *,
        category_id: str,
        remote_tools: list[str],
        suspicious_download_indicators: list[str],
        installer_language: list[str],
        domains: list[str],
        risky_flow: bool,
    ) -> float:
        confidence = 0.35
        if category_id != "unknown":
            confidence += 0.10
        if domains:
            confidence += 0.10
        if remote_tools:
            confidence += 0.18
        if suspicious_download_indicators:
            confidence += 0.15
        if installer_language:
            confidence += 0.08
        if risky_flow:
            confidence += 0.08
        return round(min(confidence, 0.94), 4)

    def _summary(self, risk_score: float, risky_flow: bool, remote_tools: list[str]) -> str:
        if risky_flow or (remote_tools and risk_score >= 0.55):
            return "This email may be trying to make the user install a remote access tool."
        if risk_score >= 0.35:
            return "This email has remote-access or installer lure indicators that need review."
        return "This email has a lure theme, but no complete remote-access installation flow was found."

    def _flow(
        self,
        domains: list[str],
        fake_document_markers: list[str],
        dangerous_files: list[str],
        installer_language: list[str],
    ) -> list[str]:
        flow: list[str] = []
        if domains:
            flow.append("email_link")
        if fake_document_markers:
            flow.append("fake_document_or_update_page")
        if dangerous_files:
            flow.append("executable_download")
        elif installer_language:
            flow.append("installer_or_remote_support_prompt")
        return flow

    def _evidence(self, details: dict) -> list[dict]:
        evidence = [{"type": "summary", "text": details["summary"]}]
        category = details.get("lure_category") or {}
        if category.get("id") and category["id"] != "unknown":
            evidence.append({
                "type": "lure_category",
                "text": f"Lure category: {category.get('label')}",
            })
        tools = details.get("detected_remote_tool_keywords") or []
        if tools:
            evidence.append({
                "type": "remote_tool",
                "text": f"Remote access tool keyword(s): {', '.join(tools[:5])}",
            })
        indicators = details.get("suspicious_download_indicators") or []
        if indicators:
            evidence.append({
                "type": "download",
                "text": indicators[0],
            })
        if details.get("risky_flow"):
            evidence.append({
                "type": "flow",
                "text": "Risky flow: email link to document/update lure with installer-style download indicators.",
            })
        guidance = details.get("user_guidance") or []
        if guidance:
            evidence.append({
                "type": "guidance",
                "text": " ".join(guidance),
            })
        return evidence[:8]

    @staticmethod
    def _extension(name: str) -> str:
        value = (name or "").lower().split("?", 1)[0].split("#", 1)[0]
        if "." not in value:
            return ""
        return "." + value.rsplit(".", 1)[1]
