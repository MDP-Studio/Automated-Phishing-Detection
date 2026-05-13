# ML Dataset Plan

This project should not train one broad model on one broad dataset and call it
done. Use separate datasets for separate questions, then hold out real product
examples for final acceptance testing.

## Prompt-Injection / Agent Safety

Best first choices:

- **LLMail-Inject**:
  https://huggingface.co/datasets/microsoft/llmail-inject-challenge

  Use for attack examples because it is email-assistant specific. The challenge
  simulated attackers sending emails that attempted to make an LLM-integrated
  mail client perform unintended actions.

- **AgentDojo / AgentDojo-Inspect**:
  https://arxiv.org/abs/2406.13352
  https://catalog.data.gov/dataset/agentdojo-inspect

  Use for tool-boundary evaluation rather than pure text classification. This is
  useful once the product has any agent-like workflow that can call tools.

- **Lakera prompt-injection collections**:
  https://docs.lakera.ai/docs/datasets
  https://huggingface.co/datasets/Lakera/mosscap_prompt_injection

  Use as extra adversarial text, but keep it separate from email-specific tests
  because many samples are game/jailbreak prompts rather than realistic emails.

## Phishing / Ham / Spam

Useful sources:

- **Seven Phishing/Spam Email Datasets**:
  https://huggingface.co/datasets/puyang2025/seven-phishing-email-datasets

  Useful for baseline text classifiers and robustness checks. Treat the labels
  carefully because phishing and spam may be merged depending on source.

- **Enron email corpus**:
  https://www.cs.cmu.edu/~enron/

  Useful for non-malicious workplace email and false-positive testing. Handle it
  as sensitive historical email data and avoid training/test leakage across
  threads or near-duplicates.

- Existing repo fixtures:
  `tests/real_world_samples/`, `demo_samples/agent_payment/`, and collected
  locally redacted product examples.

## Recommended Split

Use four evaluation lanes:

1. Prompt-injection attack detection:
   LLMail-Inject plus synthetic hidden HTML and encoded instruction variants.

2. Normal-email false positives:
   Enron, local legitimate invoices, university invoices, receipts, newsletters,
   and SaaS notification emails.

3. Phishing and payment scam detection:
   existing repo samples plus public phishing/spam corpora.

4. Agent boundary tests:
   AgentDojo-style tasks where the correct result is refusing tool actions even
   when the email text asks for them.

## Training Rule

Start with rule-based detection and evals. Train a model only after the eval
set has enough false positives and false negatives to show what the rules cannot
cover.

If a model is added later:

- keep prompt-injection detection local and cheap
- never let the model execute tools
- report model output as evidence, not authority
- split by source, thread, sender domain, and near-duplicate cluster
- redact PII before committing or publishing examples
