"""Optional LLM summary layer for normalized analyzer evidence."""

from __future__ import annotations
import logging

import json
import re
from typing import Any

from src.analyzers.clients.anthropic_client import LLMResponse

logger = logging.getLogger(__name__)


class LLMEvidenceSummarizer:
    """Summarize structured analyzer evidence without deciding verdicts."""

    def __init__(self, llm_client: object) -> None:
        self.llm_client = llm_client

    async def summarize(self, payload: dict) -> dict:
        prompt = _summary_prompt(payload)
        response = await self.llm_client.analyze(prompt)
        text, model_id = _response_text_and_model(response)
        parsed = _parse_summary_json(text)
        return {
            "source": "llm_evidence_summarizer",
            "llm_backed": True,
            "llm_status": "success",
            "model_id": model_id,
            "summary": parsed["summary"],
            "supporting_evidence": parsed["supporting_evidence"],
            "recommended_actions": parsed["recommended_actions"],
            "confidence_note": parsed["confidence_note"],
        }


def create_evidence_summary_client(api: Any) -> object | None:
    """Create the configured LLM client, or None if no key is configured."""
    provider = str(getattr(api, "llm_provider", "") or "deepseek").strip().lower()
    if provider in {"anthropic", "claude"} and getattr(api, "anthropic_key", ""):
        from src.analyzers.clients.anthropic_client import AnthropicLLMClient

        return AnthropicLLMClient(
            api.anthropic_key,
            model=api.llm_model or "claude-haiku-4-5-20251001",
        )

    from src.analyzers.clients.openai_compatible_client import OpenAICompatibleLLMClient

    if provider == "deepseek" and (api.deepseek_key or api.llm_api_key):
        return OpenAICompatibleLLMClient(
            api.deepseek_key or api.llm_api_key,
            base_url=api.llm_api_base or "https://api.deepseek.com",
            model=api.llm_model or "deepseek-v4-flash",
        )
    if provider in {"moonshot", "kimi"} and (api.moonshot_key or api.llm_api_key):
        return OpenAICompatibleLLMClient(
            api.moonshot_key or api.llm_api_key,
            base_url=api.llm_api_base or "https://api.moonshot.ai/v1",
            model=api.llm_model or "kimi-k2.6",
        )
    if provider == "gemini" and (api.gemini_key or api.llm_api_key):
        return OpenAICompatibleLLMClient(
            api.gemini_key or api.llm_api_key,
            base_url=api.llm_api_base or "https://generativelanguage.googleapis.com/v1beta/openai",
            model=api.llm_model or "gemini-3-flash-preview",
        )
    if provider in {"openai", "openai_compatible"} and (api.openai_key or api.llm_api_key):
        return OpenAICompatibleLLMClient(
            api.openai_key or api.llm_api_key,
            base_url=api.llm_api_base or "https://api.openai.com/v1",
            model=api.llm_model or "gpt-5.4-mini",
        )
    return None


def _summary_prompt(payload: dict) -> str:
    product_verdicts = payload.get("product_verdicts") or {}
    analyzer_rows = []
    for result in (payload.get("analyzer_results") or {}).values():
        analyzer_rows.append({
            "analyzer_id": result.get("analyzer_id"),
            "display_name": result.get("display_name"),
            "status": result.get("status"),
            "cost_tier": result.get("cost_tier"),
            "risk_contribution": result.get("risk_contribution"),
            "failure_reason": _safe_prompt_text(result.get("failure_reason")),
            "evidence": [
                _safe_prompt_text(item.get("text") if isinstance(item, dict) else item)
                for item in (result.get("evidence") or [])[:4]
            ],
        })
    structured = {
        "phishanalyze": product_verdicts.get("phishanalyze"),
        "payshield": product_verdicts.get("payshield"),
        "overall_score": payload.get("overall_score"),
        "overall_confidence": payload.get("overall_confidence"),
        "analyzers": analyzer_rows,
    }
    return (
        "Explain this scan using only the structured evidence below. "
        "Do not decide or change the verdict. Do not mention raw email content, "
        "legal approval, or payment authorization. Return JSON with keys: "
        "summary, supporting_evidence, recommended_actions, confidence_note.\n\n"
        f"{json.dumps(structured, ensure_ascii=True)}"
    )


def _response_text_and_model(response: Any) -> tuple[str, str]:
    if isinstance(response, LLMResponse):
        return response.text, response.model_id
    if hasattr(response, "text") and hasattr(response, "model_id"):
        return str(response.text), str(response.model_id)
    if isinstance(response, tuple) and len(response) == 2:
        return str(response[0]), str(response[1])
    return str(response), ""


def _parse_summary_json(text: str) -> dict:
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0]
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        logger.debug("Suppressed exception in src/llm_evidence_summarizer.py", exc_info=True)
        parsed = {"summary": text}
    return {
        "summary": str(parsed.get("summary") or "Structured evidence summary was generated."),
        "supporting_evidence": _string_list(parsed.get("supporting_evidence")),
        "recommended_actions": _string_list(parsed.get("recommended_actions")),
        "confidence_note": str(parsed.get("confidence_note") or "This explains evidence and does not decide the verdict."),
    }


def _safe_prompt_text(value: Any, max_length: int = 240) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = re.sub(
        r"(?i)(api[_ -]?key|token|secret|password)\s*[:=]\s*[^\s,;]+",
        r"\1=[redacted]",
        text,
    )
    text = re.sub(
        r"(?i)\b(sk|pk|rk)_(live|test)_[A-Za-z0-9_\-]+",
        "[redacted-key]",
        text,
    )
    return text[:max_length]


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item][:6]
    if value:
        return [str(value)]
    return []
