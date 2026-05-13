# AI-Agent Prompt Injection Controls

Emails are untrusted input. This matters even when no user clicks a link,
because mailbox monitoring, LLM summaries, and future agent workflows may read
email content automatically.

## Current Control

`agent_prompt_injection` is a free local analyzer. It does not call external
APIs and it does not decide the phishing verdict by itself.

It flags:

- direct attempts to override scanner or assistant instructions
- requests to reveal system prompts, developer messages, API keys, tokens, or
  credentials
- instructions aimed at an AI agent or automation tool to call tools, open
  links, use a browser, delete history, change settings, or send scan contents
- email-assistant exfiltration attempts that ask the reader or automation to
  send a message, API call, result, payload, or confirmation signal to an
  outside address
- hidden HTML instructions in comments, invisible spans, hidden style blocks, or
  similar concealment patterns
- base64-encoded instructions that decode into agent-targeting text
- simple padded-word obfuscation seen in LLMail-style samples, such as filler
  words inserted between action terms

Clean emails return `skipped` so the analyzer does not dilute normal scoring.
Detected attacks appear in the standard result contract as `AI instruction
safety`.

Routine user-facing text such as "open this link to view your invoice" is not
enough by itself. The analyzer looks for agent, LLM, tool, hidden-instruction,
override, secret-disclosure, or structured exfiltration context before
reporting a signal. Normal invoice wording such as "email us with questions" or
"send payment confirmation" should stay skipped unless it also contains
automation/action-payload indicators.

## Runtime Boundary

The product rule is structural:

- email content is data, not instructions
- LLM summaries should use structured evidence and sanitized excerpts
- email text must not trigger browser, API, mailbox, billing, deletion, or
  settings actions
- any URL or attachment action must stay inside existing sandbox, SSRF, timeout,
  and plan-gating controls

## Why This Exists

OWASP lists prompt injection as an LLM application risk and calls out failures
where crafted input can manipulate model behavior, expose data, or affect
decisions. The LLMail-Inject challenge is especially relevant because it
modeled malicious instructions embedded in emails that an LLM email assistant
retrieved and acted on.

Useful references:

- OWASP Top 10 for LLM Applications:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
- LLMail-Inject paper:
  https://arxiv.org/abs/2506.09956
- LLMail-Inject dataset:
  https://huggingface.co/datasets/microsoft/llmail-inject-challenge
- AgentDojo paper:
  https://arxiv.org/abs/2406.13352
- NIST AgentDojo-Inspect:
  https://catalog.data.gov/dataset/agentdojo-inspect
