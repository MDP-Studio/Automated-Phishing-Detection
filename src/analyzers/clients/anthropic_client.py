"""
Anthropic Claude LLM client for NLP intent analysis.

Determinism contract:
- temperature=0 — same input produces same output for a given model
- top_p=1 — disables nucleus sampling so temperature alone controls
  determinism. Without this, top_p<1 can reintroduce nondeterminism even
  at temperature=0 because the candidate set still varies token-by-token.
- The model ID the API actually used is captured per-call so that any
  divergence from the configured model (Anthropic ships periodic point
  releases) is visible in PipelineResult and can be detected after the
  fact when investigating a verdict that "should have" been the same.

If you change any of these, also update docs/EVALUATION.md §3.2 which
calls them out as the things to pin during reproducible evaluation.
"""
from __future__ import annotations

import logging
from typing import NamedTuple

import anthropic

logger = logging.getLogger(__name__)


class LLMResponse(NamedTuple):
    """
    Structured response from the LLM client.

    text:     model output (expected to be JSON by the caller)
    model_id: the model ID the API actually used. May differ from the
              requested model when Anthropic routes a versioned alias to
              a specific point release.
    """

    text: str
    model_id: str


class AnthropicLLMClient:
    """Thin wrapper around the Anthropic API for LLM-based email intent analysis."""

    def __init__(self, api_key: str, model: str = "claude-haiku-4-5-20251001"):
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = model

    async def analyze(self, prompt: str) -> LLMResponse:
        """
        Send prompt to Claude and return the response text + model used.

        Args:
            prompt: Prompt string to send to the model.

        Returns:
            LLMResponse with the response text and the actual model ID
            the API used. Callers that need backward-compatible unpacking
            should treat the result as a 2-tuple `(text, model_id)`.
        """
        message = await self._client.messages.create(
            model=self.model,
            max_tokens=512,
            temperature=0,  # deterministic: same input -> same output
            top_p=1,        # nucleus sampling disabled (with temperature=0
                            # this keeps generation fully greedy)
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text
        # `message.model` is the actual model the API used; falls back to
        # the requested model if the SDK ever omits the field.
        model_id = getattr(message, "model", None) or self.model
        return LLMResponse(text=text, model_id=model_id)
