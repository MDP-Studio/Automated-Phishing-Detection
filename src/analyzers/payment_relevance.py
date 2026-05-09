"""High-recall payment relevance classifier for PayShield routing."""

from __future__ import annotations

import re
from dataclasses import asdict
from html import unescape

from src.models import (
    AnalyzerResult,
    AttachmentObject,
    EmailObject,
    PaymentRelevanceAnalysis,
    PaymentRelevanceLabel,
)


class PaymentRelevanceAnalyzer:
    """
    Decide whether an email is payment-related before expensive PayShield work.

    The gate is intentionally high recall: invoice, billing, receipt,
    payment-request, bank-detail-change, and unknown/short cases continue to the
    full analyzer pipeline. Only clear non-payment messages are skipped.
    """

    INVOICE_TERMS = (
        "invoice",
        "tax invoice",
        "inv-",
        "inv ",
        "inv redacted",
        "proforma",
        "purchase order",
        "po number",
        "po-",
        "quote",
        "statement attached",
    )
    PAYMENT_REQUEST_TERMS = (
        "payment",
        "pay now",
        "payable",
        "amount due",
        "balance due",
        "outstanding balance",
        "remittance",
        "wire transfer",
        "bank transfer",
        "eft",
        "ach",
        "settlement",
        "payid",
        "checkout",
        "transaction",
        "deposit",
        "callback",
        "call back",
        "settle payment",
        "payroll",
        "accounts payable",
        "account payable",
    )
    BANK_CHANGE_PATTERNS = (
        r"new\s+(?:bank|account|payment)\s+details",
        r"updated\s+(?:bank|account|payment)\s+details",
        r"change(?:d)?\s+(?:our\s+)?(?:bank|account|payment)\s+details",
        r"bank\s+(?:account|details)\s+(?:has|have)\s+changed",
        r"account\s+details\s+(?:has|have)\s+changed",
        r"payment\s+must\s+be\s+redirected",
        r"remittance\s+account",
    )
    RECEIPT_TERMS = (
        "receipt",
        "paid receipt",
        "payment received",
        "paid in full",
        "tax receipt",
        "remittance advice",
        "transaction receipt",
    )
    BILLING_TERMS = (
        "billing",
        "bill",
        "subscription",
        "renewal",
        "overdue",
        "past due",
        "due date",
        "payment failed",
        "card declined",
        "refund",
        "charge",
        "statement",
    )
    PAYMENT_ATTACHMENT_TERMS = (
        "invoice",
        "receipt",
        "statement",
        "remittance",
        "payment",
        "quote",
        "purchase-order",
        "purchase_order",
        "po-",
    )
    AMOUNT_RE = re.compile(
        r"(?<!\w)(?:AUD|USD|EUR|GBP|A\$|\$|€|£)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b",
        re.IGNORECASE,
    )
    PAYMENT_FIELD_RE = re.compile(
        r"\b(?:bsb|iban|swift|bic|payid|account\s+(?:number|no\.?))\b",
        re.IGNORECASE,
    )

    async def analyze(
        self,
        email: EmailObject,
        iocs: dict | None = None,
        extracted_urls: list | None = None,
    ) -> AnalyzerResult:
        analysis = self.classify(email)
        details = asdict(analysis)
        details["label"] = analysis.label.value
        details["message"] = "payment_relevance_classified"
        details["ml_sidecar"] = {
            "available": False,
            "reason": "no_payment_relevance_model_configured",
        }
        return AnalyzerResult(
            analyzer_name="payment_relevance",
            risk_score=0.0,
            confidence=analysis.confidence,
            details=details,
            risk_contribution=0.0,
            cost_tier="free_local",
            evidence=[
                {"type": "summary", "text": analysis.summary},
                *[
                    {"type": "reason", "text": reason}
                    for reason in analysis.reasons[:3]
                ],
            ],
        )

    def classify(self, email: EmailObject) -> PaymentRelevanceAnalysis:
        text = self._combined_text(email)
        message_text = self._message_text(email)
        attachment_names = self._attachment_names(getattr(email, "attachments", []) or [])
        attachment_text = " ".join(attachment_names).lower()
        full_text = " ".join([text, attachment_text]).strip()
        sparse_text = " ".join([message_text, attachment_text]).strip()

        invoice_terms = self._matched_terms(full_text, self.INVOICE_TERMS)
        payment_terms = self._matched_terms(full_text, self.PAYMENT_REQUEST_TERMS)
        receipt_terms = self._matched_terms(full_text, self.RECEIPT_TERMS)
        billing_terms = self._matched_terms(full_text, self.BILLING_TERMS)
        attachment_terms = self._matched_terms(attachment_text, self.PAYMENT_ATTACHMENT_TERMS)
        bank_change = self._matched_patterns(full_text, self.BANK_CHANGE_PATTERNS)
        has_amount = bool(self.AMOUNT_RE.search(full_text))
        has_payment_field = bool(self.PAYMENT_FIELD_RE.search(full_text))

        if bank_change:
            return self._analysis(
                PaymentRelevanceLabel.BANK_DETAIL_CHANGE,
                0.96,
                True,
                "Bank-detail change language was detected, so PayShield should run the full payment-risk analysis.",
                [f"Bank-detail change phrase: {bank_change[0]}"],
                bank_change,
            )

        if invoice_terms or attachment_terms:
            reasons = []
            if invoice_terms:
                reasons.append(f"Invoice or purchase-order language: {invoice_terms[0]}")
            if attachment_terms:
                reasons.append(f"Payment-themed attachment name: {attachment_terms[0]}")
            if has_amount:
                reasons.append("Amount-like value detected.")
            return self._analysis(
                PaymentRelevanceLabel.INVOICE,
                0.90 if has_amount or attachment_terms else 0.82,
                True,
                "Invoice or purchase-order context was detected, so PayShield should scan this email.",
                reasons,
                [*invoice_terms, *attachment_terms],
            )

        if receipt_terms:
            reasons = [f"Receipt or remittance language: {receipt_terms[0]}"]
            if has_amount:
                reasons.append("Amount-like value detected.")
            return self._analysis(
                PaymentRelevanceLabel.RECEIPT,
                0.84,
                True,
                "Receipt or remittance context was detected, so PayShield should retain payment visibility.",
                reasons,
                receipt_terms,
            )

        if billing_terms:
            reasons = [f"Billing language: {billing_terms[0]}"]
            if has_amount:
                reasons.append("Amount-like value detected.")
            return self._analysis(
                PaymentRelevanceLabel.BILLING_NOTICE,
                0.82,
                True,
                "Billing or subscription context was detected, so PayShield should scan this email.",
                reasons,
                billing_terms,
            )

        if payment_terms or has_payment_field or has_amount:
            reasons = []
            if payment_terms:
                reasons.append(f"Payment request language: {payment_terms[0]}")
            if has_payment_field:
                reasons.append("Payment account field language detected.")
            if has_amount:
                reasons.append("Amount-like value detected.")
            return self._analysis(
                PaymentRelevanceLabel.PAYMENT_REQUEST,
                0.78,
                True,
                "Payment request context was detected, so PayShield should scan this email.",
                reasons,
                payment_terms,
            )

        if len(sparse_text) < 40:
            return self._analysis(
                PaymentRelevanceLabel.UNKNOWN,
                0.45,
                True,
                "The email content was too short to safely rule out payment relevance.",
                ["Short or sparse content."],
                [],
            )

        return self._analysis(
            PaymentRelevanceLabel.NON_PAYMENT,
            0.91,
            False,
            "No invoice, billing, receipt, bank-detail, amount, or payment-request context was detected.",
            ["No payment-relevance terms or payment fields matched."],
            [],
        )

    def _analysis(
        self,
        label: PaymentRelevanceLabel,
        confidence: float,
        should_scan: bool,
        summary: str,
        reasons: list[str],
        matched_terms: list[str],
    ) -> PaymentRelevanceAnalysis:
        return PaymentRelevanceAnalysis(
            label=label,
            confidence=round(max(0.0, min(confidence, 1.0)), 3),
            should_scan=should_scan,
            summary=summary,
            reasons=reasons,
            matched_terms=self._unique(matched_terms)[:8],
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

    def _message_text(self, email: EmailObject) -> str:
        html_text = re.sub(r"<[^>]+>", " ", email.body_html or "")
        return unescape(
            " ".join([
                email.subject or "",
                email.body_plain or "",
                html_text,
            ])
        ).lower()

    def _attachment_names(self, attachments: list[AttachmentObject]) -> list[str]:
        names = []
        for attachment in attachments:
            if attachment.filename:
                names.append(attachment.filename)
            names.extend(self._attachment_names(attachment.nested_files or []))
        return names

    def _matched_terms(self, text: str, terms: tuple[str, ...]) -> list[str]:
        matches = []
        for term in terms:
            if term.endswith("-"):
                pattern = r"(?<![a-z0-9])" + re.escape(term) + r"[a-z0-9]"
            elif term.endswith(" "):
                pattern = r"(?<![a-z0-9])" + re.escape(term.rstrip()) + r"\s+[a-z0-9]"
            else:
                pattern = r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])"
            if re.search(pattern, text):
                matches.append(term)
        return self._unique(matches)

    def _matched_patterns(self, text: str, patterns: tuple[str, ...]) -> list[str]:
        matches = []
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                matches.append(match.group(0))
        return self._unique(matches)

    def _unique(self, values: list[str]) -> list[str]:
        seen = set()
        result = []
        for value in values:
            normalized = re.sub(r"\s+", " ", str(value or "").strip().lower())
            if normalized and normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
        return result
