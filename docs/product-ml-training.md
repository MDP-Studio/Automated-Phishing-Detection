# Product ML Training Guide

This project has separate model lanes for PhishAnalyze and PayShield. Do not
merge them into one generic classifier.

## Product Lanes

| Lane | Model target | Why separate |
| --- | --- | --- |
| PhishAnalyze | `CLEAN` vs `PHISHING` baseline | Broad suspicious-email detection needs phishing, spam, and ham corpora. |
| PayShield | `SAFE`, `VERIFY`, `DO_NOT_PAY` | Payment decision support needs invoice, bank-change, BEC, and supplier-risk labels. |
| Shared prompt-injection safety | Analyzer/eval lane, not product verdict authority | Prompt-injection content is hostile input that both products must surface, but it should not replace product-specific labels. |

PhishAnalyze answers: "is this suspicious or phishing?"

PayShield answers: "should finance continue normal checks, verify out of band,
or pause payment?"

The prompt-injection lane answers: "is the email trying to control AI tools,
prompts, secrets, browser actions, mailbox actions, or account state?"

## No-Oversampling Rule

Do not duplicate rows to balance classes. Current scripts may use deterministic
sampling for fixed evaluation slices, and sklearn may use `class_weight`, but
that is not row oversampling.

Use two corpus shapes:

- Stable slice: small deterministic sample for repeatable comparisons.
- Full no-oversample corpus: every available candidate the current preparer can
  read from the downloaded corpora.

Keep both. Do not replace the stable 500-sample slice with the full corpus.
The 500-sample slice may be regenerated with `--clean-output`; that replaces
only the prepared slice folder, not the raw downloaded corpora.

## Remote Paths

Remote repo:

```bash
/home/meidie/.openclaw/workspace/Automated-Phishing-Detection
```

Raw corpora:

```bash
data/corpora/
data/corpora/huggingface/
```

Prepared corpora:

```bash
data/eval_corpus
data/eval_corpus_full_no_oversample
```

Model artifacts:

```bash
models/phishing_classifier
models/phishanalyze_classifier_full_no_oversample
models/payment_classifier
models/prompt_injection_classifier
```

These folders are intentionally ignored by Git.

## PhishAnalyze Commands

Stable 500-sample slice:

```bash
python3 scripts/eval_prepare_corpus.py \
  --corpora-dir data/corpora \
  --output data/eval_corpus \
  --phishing 200 \
  --enron-ham 200 \
  --spamassassin-ham 100 \
  --clean-output
```

Full no-oversample corpus:

```bash
python3 scripts/eval_prepare_corpus.py \
  --corpora-dir data/corpora \
  --output data/eval_corpus_full_no_oversample \
  --phishing 999999 \
  --enron-ham 999999 \
  --spamassassin-ham 999999 \
  --clean-output
```

Train inside Docker:

```bash
docker exec phishing-orchestrator python scripts/phishing_train.py \
  --corpus /app/data/eval_corpus_full_no_oversample \
  --output-dir /app/models/phishanalyze_classifier_full_no_oversample
```

## PayShield Commands

Check dataset readiness:

```bash
docker exec phishing-orchestrator python scripts/payment_dataset.py readiness \
  --dataset /app/data/payment_scam_dataset
```

Train PayShield decision model:

```bash
docker exec phishing-orchestrator python scripts/payment_train.py \
  --dataset /app/data/payment_scam_dataset \
  --output-dir /app/models/payment_classifier
```

## Prompt-Injection Coverage

Prompt-injection coverage is shared across both products through the
`agent_prompt_injection` analyzer. The downloaded datasets for this lane are:

- LLMail-Inject: `data/corpora/huggingface/microsoft__llmail-inject-challenge`
- Lakera MOSSCap: `data/corpora/huggingface/Lakera__mosscap_prompt_injection`
- AgentDojo-style references listed in `docs/ml-datasets.md`

Use these datasets for hostile-input evaluation and future ML experiments.
Do not let a prompt-injection model execute tools or decide final product
verdicts from scratch.

Current product decision:

- keep PhishAnalyze and PayShield classifiers separate
- keep prompt injection as a shared hostile-input safety lane
- surface prompt-injection evidence in both products when the shared analyzer
  fires
- do not relabel generic prompt-injection samples as PayShield invoice fraud
  unless the email is actually payment-specific

Prepare the shared ML dataset. This uses LLMail attacks as
`PROMPT_INJECTION`, LLMail benign FP examples as `CLEAN`, and clean
Enron/SpamAssassin mail from the full no-oversample PhishAnalyze corpus as
`CLEAN`.

```bash
docker exec phishing-orchestrator python scripts/prompt_injection_dataset.py \
  --llmail-dir /app/data/corpora/huggingface/microsoft__llmail-inject-challenge/data \
  --clean-corpus-dir /app/data/eval_corpus_full_no_oversample \
  --output /app/data/prompt_injection_corpus/prompt_injection_ml.jsonl
```

Train the shared prompt-injection classifier:

```bash
docker exec phishing-orchestrator python scripts/prompt_injection_train.py \
  --dataset /app/data/prompt_injection_corpus/prompt_injection_ml.jsonl \
  --output-dir /app/models/prompt_injection_classifier
```

Runtime use:

- `agent_prompt_injection` still works without the model.
- When `models/prompt_injection_classifier/prompt_injection_model.joblib`
  exists, the analyzer uses it as an extra signal behind
  `PROMPT_INJECTION_ML_THRESHOLD`.
- The ML signal can explain hostile-input similarity, but it must not execute
  tools or become the only final verdict authority.
