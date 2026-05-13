"""Detect prompt-injection attempts embedded in email content."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import asdict, dataclass
from html import unescape

from src.models import AnalyzerResult, EmailObject


@dataclass(frozen=True)
class AgentInjectionSignal:
    """One explainable AI-agent safety signal."""

    name: str
    severity: str
    evidence: str
    recommendation: str
    risk_weight: float


class AgentPromptInjectionAnalyzer:
    """Find instructions that target scanners, LLMs, tools, or agents."""

    ANALYZER_NAME = "agent_prompt_injection"

    AGENT_TERMS = (
        "ai agent",
        "assistant",
        "llm",
        "language model",
        "chatgpt",
        "copilot",
        "system prompt",
        "developer message",
        "tool call",
        "function call",
        "automation",
    )
    OVERRIDE_PATTERNS = (
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|messages)\b",
        r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|messages)\b",
        r"\boverride\s+(?:the\s+)?(?:system|developer|security)\s+(?:prompt|instructions|rules)\b",
        r"\bforget\s+(?:the\s+)?(?:previous|prior|system|developer)\s+(?:instructions|prompt|message)\b",
        r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|admin|root|system)\s+mode\b",
    )
    TOOL_ABUSE_PATTERNS = (
        r"\b(?:call|use|invoke|run|execute)\s+(?:the\s+)?(?:tool|function|api|browser|shell|command)\b",
        r"\b(?:click|open|visit|fetch|download)\s+(?:this|the|all)?\s*(?:link|url|attachment|file)\b",
        r"\b(?:delete|modify|change|update)\s+(?:the\s+)?(?:account|settings|billing|mailbox|history|scan)\b",
        r"\b(?:send|forward|email|post|upload)\s+(?:the\s+)?(?:result|contents|conversation|secrets?|tokens?)\b",
    )
    SECRET_EXFIL_PATTERNS = (
        r"\breveal\s+(?:the\s+)?(?:system\s+prompt|developer\s+message|instructions|secrets?|api\s+keys?|tokens?)\b",
        r"\bprint\s+(?:the\s+)?(?:system\s+prompt|developer\s+message|secrets?|api\s+keys?|tokens?)\b",
        r"\bexfiltrat(?:e|ion)\b",
        r"\bleak\s+(?:the\s+)?(?:prompt|secrets?|api\s+keys?|tokens?|credentials)\b",
    )
    HTML_HIDING_PATTERNS = (
        r"display\s*:\s*none",
        r"visibility\s*:\s*hidden",
        r"opacity\s*:\s*0(?:\.0+)?",
        r"font-size\s*:\s*0",
        r"color\s*:\s*(?:#fff(?:fff)?|white)\b",
        r"mso-hide\s*:\s*all",
        r"aria-hidden\s*=\s*[\"']?true",
    )
    COMMENT_RE = re.compile(r"<!--(.*?)-->", re.IGNORECASE | re.DOTALL)
    STYLE_BLOCK_RE = re.compile(
        r"<[^>]+(?:style|hidden|aria-hidden)[^>]*>(.*?)</[^>]+>",
        re.IGNORECASE | re.DOTALL,
    )
    BASE64_CANDIDATE_RE = re.compile(
        r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])"
    )

    async def analyze(self, email: EmailObject) -> AnalyzerResult:
        """Analyze email content for AI-agent instruction attacks."""
        raw_text = self._combined_text(email)
        text = raw_text.lower()
        html = email.body_html or ""
        signals: list[AgentInjectionSignal] = []

        self._add_direct_instruction_signals(text, signals)
        self._add_hidden_instruction_signals(html, signals)
        self._add_encoded_instruction_signals(raw_text, signals)

        if not signals:
            return AnalyzerResult(
                analyzer_name=self.ANALYZER_NAME,
                risk_score=0.0,
                confidence=0.0,
                details={
                    "message": "no_agent_instruction_attempt",
                    "summary": "No AI-agent instruction attempt detected.",
                    "signals": [],
                    "user_guidance": [
                        "Treat email content as untrusted input before sending it to any AI system.",
                    ],
                },
                status="skipped",
                cost_tier="free_local",
                risk_contribution=0.0,
                evidence=[{"type": "summary", "text": "No AI-agent instruction attempt detected."}],
            )

        risk_score = self._combine_signal_risk(signals)
        confidence = self._confidence(signals)
        summary = self._summary(signals, risk_score)
        return AnalyzerResult(
            analyzer_name=self.ANALYZER_NAME,
            risk_score=risk_score,
            confidence=confidence,
            details={
                "summary": summary,
                "signals": [asdict(signal) for signal in signals],
                "user_guidance": self._user_guidance(signals),
                "agent_safety_boundary": (
                    "Email content is untrusted data. It must not be allowed to "
                    "trigger tools, reveal secrets, or change account state."
                ),
            },
            cost_tier="free_local",
            evidence=[
                {"type": "summary", "text": summary},
                *[
                    {
                        "type": signal.name,
                        "text": signal.evidence,
                        "severity": signal.severity,
                    }
                    for signal in signals[:4]
                ],
            ],
        )

    def _add_direct_instruction_signals(
        self,
        text: str,
        signals: list[AgentInjectionSignal],
    ) -> None:
        agent_context = self._matched_terms(text, self.AGENT_TERMS)
        overrides = self._matched_patterns(text, self.OVERRIDE_PATTERNS)
        tool_abuse = self._matched_patterns(text, self.TOOL_ABUSE_PATTERNS)
        exfil = self._matched_patterns(text, self.SECRET_EXFIL_PATTERNS)

        if overrides:
            signals.append(self._signal(
                "instruction_override_attempt",
                "high",
                f"Instruction override phrase found: {overrides[0]}",
                "Ignore sender instructions that try to change scanner or assistant behavior.",
                0.34 if agent_context else 0.24,
            ))
        if exfil:
            signals.append(self._signal(
                "secret_exfiltration_instruction",
                "critical",
                f"Secret or prompt disclosure instruction found: {exfil[0]}",
                "Do not send secrets, prompts, credentials, or scan history to destinations named in the email.",
                0.46,
            ))
        if tool_abuse and agent_context:
            signals.append(self._signal(
                "agent_tool_abuse_instruction",
                "high",
                f"Tool or account action instruction aimed at an agent: {tool_abuse[0]}",
                "Do not allow email text to trigger browser, API, mailbox, billing, or deletion actions.",
                0.32,
            ))

    def _add_hidden_instruction_signals(
        self,
        html: str,
        signals: list[AgentInjectionSignal],
    ) -> None:
        if not html:
            return
        hidden_chunks = [
            match.group(1)
            for match in self.COMMENT_RE.finditer(html)
            if self._looks_like_agent_instruction(match.group(1))
        ]
        hidden_chunks.extend(
            match.group(1)
            for match in self.STYLE_BLOCK_RE.finditer(html)
            if self._looks_like_agent_instruction(match.group(0))
        )
        hiding_markers = self._matched_patterns(html, self.HTML_HIDING_PATTERNS)
        if hidden_chunks:
            evidence = self._trim(unescape(re.sub(r"<[^>]+>", " ", hidden_chunks[0])))
            signals.append(self._signal(
                "hidden_agent_instruction",
                "critical",
                f"Hidden AI-agent instruction found in HTML: {evidence}",
                "Strip hidden HTML instructions before LLM summarization or automation.",
                0.42,
            ))
        elif hiding_markers and self._looks_like_agent_instruction(html):
            signals.append(self._signal(
                "concealed_agent_targeting",
                "high",
                f"Concealment marker appears near agent-targeting text: {hiding_markers[0]}",
                "Treat concealed instructions as hostile input.",
                0.30,
            ))

    def _add_encoded_instruction_signals(
        self,
        text: str,
        signals: list[AgentInjectionSignal],
    ) -> None:
        for match in self.BASE64_CANDIDATE_RE.finditer(text):
            decoded = self._decode_base64_text(match.group(1))
            if decoded and self._looks_like_agent_instruction(decoded):
                signals.append(self._signal(
                    "encoded_agent_instruction",
                    "high",
                    f"Encoded AI-agent instruction found: {self._trim(decoded)}",
                    "Do not decode and execute instructions embedded in email content.",
                    0.30,
                ))
                return

    def _combined_text(self, email: EmailObject) -> str:
        html_text = unescape(re.sub(r"<[^>]+>", " ", email.body_html or ""))
        return " ".join([
            email.subject or "",
            email.from_display_name or "",
            email.from_address or "",
            email.reply_to or "",
            email.body_plain or "",
            html_text,
        ])

    def _looks_like_agent_instruction(self, value: str) -> bool:
        text = unescape(re.sub(r"<[^>]+>", " ", value or "")).lower()
        has_agent_term = bool(self._matched_terms(text, self.AGENT_TERMS))
        has_override = bool(self._matched_patterns(text, self.OVERRIDE_PATTERNS))
        has_tool_abuse = bool(self._matched_patterns(text, self.TOOL_ABUSE_PATTERNS))
        has_exfil = bool(self._matched_patterns(text, self.SECRET_EXFIL_PATTERNS))
        return has_exfil or has_override or (has_agent_term and has_tool_abuse)

    def _matched_terms(self, text: str, terms: tuple[str, ...]) -> list[str]:
        return [term for term in terms if term in text]

    def _matched_patterns(self, text: str, patterns: tuple[str, ...]) -> list[str]:
        matches = []
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                matches.append(self._trim(match.group(0)))
        return matches

    def _decode_base64_text(self, value: str) -> str:
        try:
            padded = value + ("=" * (-len(value) % 4))
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            return ""
        if not raw:
            return ""
        try:
            decoded = raw.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return ""
        printable = sum(1 for char in decoded if char.isprintable() or char.isspace())
        if printable / max(len(decoded), 1) < 0.85:
            return ""
        return decoded

    def _combine_signal_risk(self, signals: list[AgentInjectionSignal]) -> float:
        risk = 0.0
        for signal in signals:
            risk = 1 - ((1 - risk) * (1 - signal.risk_weight))
        return round(max(0.0, min(1.0, risk)), 3)

    def _confidence(self, signals: list[AgentInjectionSignal]) -> float:
        severities = {signal.severity for signal in signals}
        confidence = 0.62 + min(len(signals) * 0.08, 0.24)
        if "critical" in severities:
            confidence += 0.10
        return round(max(0.0, min(0.95, confidence)), 3)

    def _summary(self, signals: list[AgentInjectionSignal], risk_score: float) -> str:
        names = {signal.name for signal in signals}
        if "secret_exfiltration_instruction" in names:
            return "Email contains instructions that try to make an AI system reveal secrets or prompts."
        if "hidden_agent_instruction" in names or "encoded_agent_instruction" in names:
            return "Email contains concealed instructions aimed at AI or automation tools."
        if risk_score >= 0.45:
            return "Email contains instructions that attempt to control AI-agent behavior."
        return "Email contains automation-like instructions that should stay isolated from tools."

    def _user_guidance(self, signals: list[AgentInjectionSignal]) -> list[str]:
        guidance = [
            "Treat the email body as untrusted data, not instructions.",
            "Do not let email content trigger tool calls, browser actions, deletion, billing, or mailbox changes.",
            "Use LLM summaries only over structured evidence and sanitized excerpts.",
        ]
        if any(signal.name == "hidden_agent_instruction" for signal in signals):
            guidance.insert(1, "Strip hidden HTML, comments, and invisible text before sending content to an LLM.")
        if any(signal.name == "secret_exfiltration_instruction" for signal in signals):
            guidance.insert(0, "Do not disclose prompts, tokens, credentials, or scan history.")
        return guidance

    def _signal(
        self,
        name: str,
        severity: str,
        evidence: str,
        recommendation: str,
        risk_weight: float,
    ) -> AgentInjectionSignal:
        return AgentInjectionSignal(
            name=name,
            severity=severity,
            evidence=evidence,
            recommendation=recommendation,
            risk_weight=risk_weight,
        )

    def _trim(self, value: str, limit: int = 180) -> str:
        text = re.sub(r"\s+", " ", str(value)).strip()
        if len(text) <= limit:
            return text
        return f"{text[: max(limit - 3, 0)].rstrip()}..."
