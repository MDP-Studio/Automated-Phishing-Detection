"""
Anthropic Claude LLM client for NLP intent analysis.
"""
import logging

import anthropic

logger = logging.getLogger(__name__)


class AnthropicLLMClient:
    """Thin wrapper around the Anthropic API for LLM-based email intent analysis."""

    def __init__(self, api_key: str, model: str = "claude-haiku-4-5-20251001"):
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = model

    async def analyze(self, prompt: str) -> str:
        """
        Send prompt to Claude and return the response text.

        Args:
            prompt: Prompt string to send to the model.

        Returns:
            Response text (expected to be JSON by the caller).
        """
        message = await self._client.messages.create(
            model=self.model,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
