"""
NLPIntentAnalyzer: Classify email intent using NLP.
Supports both LLM-based and local sklearn fallback approaches.
"""
import asyncio
import json
import logging
from typing import Optional

from src.models import AnalyzerResult, EmailObject, IntentCategory

logger = logging.getLogger(__name__)


class NLPIntentAnalyzer:
    """
    Classify email intent using natural language processing.

    Supports two approaches:
    1. LLM-based: Call API with structured prompt, parse JSON response
    2. Local sklearn fallback: TF-IDF + pretrained classifier

    Intent categories and risk score mapping:
    - CREDENTIAL_HARVESTING: 0.95 (very high risk)
    - MALWARE_DELIVERY: 0.90 (very high risk)
    - BEC_WIRE_FRAUD: 0.85 (high risk)
    - GIFT_CARD_SCAM: 0.80 (high risk)
    - EXTORTION: 0.75 (high risk)
    - LEGITIMATE: 0.05 (very low risk)
    - UNKNOWN: 0.30 (medium risk)

    Additional urgency score modifier (0.0 to 1.0) boosts risk for urgent language.
    """

    INTENT_RISK_MAPPING = {
        IntentCategory.CREDENTIAL_HARVESTING: 0.95,
        IntentCategory.MALWARE_DELIVERY: 0.90,
        IntentCategory.BEC_WIRE_FRAUD: 0.85,
        IntentCategory.GIFT_CARD_SCAM: 0.80,
        IntentCategory.EXTORTION: 0.75,
        IntentCategory.LEGITIMATE: 0.05,
        IntentCategory.UNKNOWN: 0.30,
    }

    URGENCY_KEYWORDS = [
        "urgent",
        "immediate",
        "asap",
        "right now",
        "immediately",
        "quickly",
        "time-sensitive",
        "within 24 hours",
        "within 48 hours",
        "act now",
        "do not delay",
        "critical",
        "emergency",
        "alert",
    ]

    def __init__(
        self,
        llm_client: Optional[object] = None,
        sklearn_classifier: Optional[object] = None,
        use_llm: bool = True,
    ):
        """
        Initialize NLP intent analyzer with dependency injection.

        Args:
            llm_client: LLM API client for intent classification
            sklearn_classifier: sklearn classifier for fallback analysis
            use_llm: Whether to prefer LLM-based approach
        """
        self.llm_client = llm_client
        self.sklearn_classifier = sklearn_classifier
        self.use_llm = use_llm

    def _calculate_urgency_score(self, text: str) -> float:
        """
        Calculate urgency score based on keywords in text.

        Args:
            text: Email text to analyze

        Returns:
            Urgency score from 0.0 to 1.0
        """
        text_lower = text.lower()
        matched_keywords = sum(
            1 for keyword in self.URGENCY_KEYWORDS
            if keyword in text_lower
        )

        # Normalize to 0-1 range
        urgency_score = min(matched_keywords / 5.0, 1.0)
        return urgency_score

    async def _analyze_with_llm(self, email: EmailObject) -> tuple[IntentCategory, float, str, float, str]:
        """
        Classify email intent using LLM.

        Args:
            email: Email object to analyze

        Returns:
            Tuple of (intent_category, confidence, reasoning, urgency_score, model_id).
            `model_id` is the LLM model the API actually used, captured per-call
            so that downstream consumers (PipelineResult, evaluation harness)
            can detect drift after Anthropic ships a model point release.
            Empty string when no LLM ran.
        """
        if not self.llm_client:
            return IntentCategory.UNKNOWN, 0.0, "No LLM client available", 0.0, ""

        try:
            # Prepare email text for analysis
            email_text = f"""
Subject: {email.subject}
From: {email.from_address} ({email.from_display_name})
Body: {email.body_plain[:2000]}
"""

            # Create structured prompt
            prompt = f"""Analyze this email and classify its intent.

Email:
{email_text}

Classify the email into one of these categories:
- credential_harvesting: Attempting to steal login credentials
- malware_delivery: Delivering malware or malicious attachments
- bec_wire_fraud: Business Email Compromise / wire fraud attempt
- gift_card_scam: Requesting gift card purchases
- extortion: Threatening or extortion content
- legitimate: Legitimate business email
- unknown: Cannot determine intent

Respond in JSON format:
{{
    "intent": "category_name",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation",
    "urgency_indicators": number of urgent phrases found
}}
"""

            llm_result = await self.llm_client.analyze(prompt)

            # llm_result is a (text, model_id) NamedTuple from
            # AnthropicLLMClient.analyze. Be defensive — older clients or
            # mocks may still return a bare string, in which case there's
            # no model_id to capture.
            if hasattr(llm_result, "text") and hasattr(llm_result, "model_id"):
                response = llm_result.text
                model_id = llm_result.model_id
            elif isinstance(llm_result, tuple) and len(llm_result) == 2:
                response, model_id = llm_result
            else:
                response = llm_result
                model_id = getattr(self.llm_client, "model", "") or ""

            # Parse JSON response
            try:
                if isinstance(response, str):
                    # Extract JSON from response if wrapped in markdown
                    if "```json" in response:
                        response = response.split("```json")[1].split("```")[0]
                    response = json.loads(response)
                elif not isinstance(response, dict):
                    response = json.loads(str(response))
            except json.JSONDecodeError:
                logger.warning("Failed to parse LLM response as JSON")
                return IntentCategory.UNKNOWN, 0.0, "JSON parse error", 0.0, model_id

            intent_str = response.get("intent", "unknown").lower()
            confidence = response.get("confidence", 0.5)
            reasoning = response.get("reasoning", "")
            urgency_indicators = response.get("urgency_indicators", 0)

            # Map string to IntentCategory enum
            try:
                intent_category = IntentCategory(intent_str)
            except ValueError:
                # Try to match with underscore conversion
                intent_str = intent_str.replace("-", "_").replace(" ", "_")
                try:
                    intent_category = IntentCategory[intent_str.upper()]
                except KeyError:
                    intent_category = IntentCategory.UNKNOWN

            urgency_score = min(urgency_indicators / 5.0, 1.0)

            return intent_category, confidence, reasoning, urgency_score, model_id

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return IntentCategory.UNKNOWN, 0.0, f"LLM error: {str(e)}", 0.0, ""

    async def _analyze_with_sklearn(self, email: EmailObject) -> tuple[IntentCategory, float, str, float]:
        """
        Classify email intent using sklearn classifier.

        Args:
            email: Email object to analyze

        Returns:
            Tuple of (intent_category, confidence, reasoning, urgency_score)
        """
        if not self.sklearn_classifier:
            return IntentCategory.UNKNOWN, 0.0, "No sklearn classifier available", 0.0

        try:
            # Prepare text for classification
            email_text = f"{email.subject} {email.body_plain[:1000]}"

            # Use sklearn classifier
            prediction = await self.sklearn_classifier.predict(email_text)

            intent_str = prediction.get("intent", "unknown")
            confidence = prediction.get("probability", 0.0)

            # Map string to IntentCategory
            try:
                intent_category = IntentCategory(intent_str)
            except ValueError:
                intent_category = IntentCategory.UNKNOWN

            reasoning = prediction.get("reasoning", "sklearn classification")
            urgency_score = self._calculate_urgency_score(email_text)

            return intent_category, confidence, reasoning, urgency_score

        except Exception as e:
            logger.error(f"sklearn analysis failed: {e}")
            return IntentCategory.UNKNOWN, 0.0, f"sklearn error: {str(e)}", 0.0

    PHISHING_KEYWORDS = [
        "verify your account", "confirm your email", "click here to verify",
        "update your payment", "your account has been suspended",
        "unusual activity", "secure your account", "login to your account",
        "reset your password", "your password has expired",
        "wire transfer", "gift card", "invoice attached",
        "urgent action required", "your account will be closed",
        "you have won", "claim your prize",
    ]

    CREDENTIAL_KEYWORDS = ["password", "username", "login", "sign in", "verify", "confirm account"]
    BEC_KEYWORDS = ["wire transfer", "invoice", "payment", "bank account", "routing number"]
    GIFT_CARD_KEYWORDS = ["gift card", "itunes", "amazon card", "google play"]
    MALWARE_KEYWORDS = ["attachment", "download", "open file", "enable macros"]

    def _analyze_with_keywords(
        self, email: EmailObject
    ) -> tuple["IntentCategory", float, str, float]:
        """
        Keyword-based intent analysis fallback (no external API needed).

        Returns:
            Tuple of (intent_category, confidence, reasoning, urgency_score)
        """
        text = f"{email.subject} {email.body_plain[:2000]}".lower()
        urgency_score = self._calculate_urgency_score(text)

        phishing_hits = sum(1 for kw in self.PHISHING_KEYWORDS if kw in text)
        credential_hits = sum(1 for kw in self.CREDENTIAL_KEYWORDS if kw in text)
        bec_hits = sum(1 for kw in self.BEC_KEYWORDS if kw in text)
        gift_card_hits = sum(1 for kw in self.GIFT_CARD_KEYWORDS if kw in text)
        malware_hits = sum(1 for kw in self.MALWARE_KEYWORDS if kw in text)

        if gift_card_hits >= 1:
            return IntentCategory.GIFT_CARD_SCAM, 0.55, "Gift card keywords detected", urgency_score
        if bec_hits >= 2:
            return IntentCategory.BEC_WIRE_FRAUD, 0.55, "BEC keywords detected", urgency_score
        if malware_hits >= 2:
            return IntentCategory.MALWARE_DELIVERY, 0.5, "Malware delivery keywords detected", urgency_score
        if credential_hits >= 2 or phishing_hits >= 1:
            return IntentCategory.CREDENTIAL_HARVESTING, 0.5, "Credential harvesting keywords detected", urgency_score
        if urgency_score >= 0.4:
            return IntentCategory.UNKNOWN, 0.4, "High urgency language detected", urgency_score

        return IntentCategory.LEGITIMATE, 0.4, "No suspicious keywords found", urgency_score

    async def analyze(self, email: EmailObject) -> AnalyzerResult:
        """
        Analyze email intent.

        Args:
            email: Email object to analyze

        Returns:
            AnalyzerResult with risk score and confidence
        """
        analyzer_name = "nlp_intent"

        try:
            if not email or not email.subject:
                return AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.0,
                    confidence=0.0,
                    details={"message": "no_email_content"},
                )

            # Try LLM first, fall back to sklearn, then keyword analysis.
            # `model_id` is captured only on the LLM path; sklearn / keyword
            # paths set it to "" so PipelineResult always carries a string.
            model_id = ""
            if self.use_llm:
                intent_category, confidence, reasoning, urgency_score, model_id = (
                    await self._analyze_with_llm(email)
                )
                method = "llm"

                if confidence == 0.0 and self.sklearn_classifier:
                    logger.info("LLM failed or inconclusive, falling back to sklearn")
                    intent_category, confidence, reasoning, urgency_score = (
                        await self._analyze_with_sklearn(email)
                    )
                    method = "sklearn_fallback"
                    model_id = ""
            else:
                intent_category, confidence, reasoning, urgency_score = (
                    await self._analyze_with_sklearn(email)
                )
                method = "sklearn"

            # Final fallback: keyword-based analysis (always produces a result)
            if confidence == 0.0:
                intent_category, confidence, reasoning, urgency_score = (
                    self._analyze_with_keywords(email)
                )
                method = "keywords"
                model_id = ""

            # Map intent to risk score
            base_risk_score = self.INTENT_RISK_MAPPING.get(
                intent_category, 0.3
            )

            # Apply urgency modifier
            # Urgency increases risk, especially for suspicious intents
            urgency_modifier = urgency_score * 0.2 if base_risk_score > 0.5 else urgency_score * 0.1
            final_risk_score = min(base_risk_score + urgency_modifier, 1.0)

            logger.info(
                f"Intent analysis complete: "
                f"intent={intent_category.value}, "
                f"risk={final_risk_score:.2f}, "
                f"confidence={confidence:.2f}, "
                f"urgency={urgency_score:.2f}"
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=final_risk_score,
                confidence=confidence,
                details={
                    "intent_category": intent_category.value,
                    "base_risk_score": base_risk_score,
                    "urgency_score": urgency_score,
                    "urgency_modifier": urgency_modifier,
                    "reasoning": reasoning,
                    "analysis_method": method,
                    # LLM model the API actually used for this analysis.
                    # Captured per-result for drift detection — see
                    # docs/EVALUATION.md §3.2 and the determinism contract
                    # in src/analyzers/clients/anthropic_client.py.
                    "llm_model_version": model_id,
                },
            )

        except Exception as e:
            logger.error(f"NLP intent analysis failed: {e}")
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )
