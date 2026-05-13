# ML Training Runs

This file records local/remote training artifacts so future agents do not
confuse raw corpora, stable eval slices, full corpora, and model outputs.

## Current Remote State

Remote host:

```bash
meidie@100.110.79.52
```

Remote repo:

```bash
/home/meidie/.openclaw/workspace/Automated-Phishing-Detection
```

Current code commit used for the dataset download and first training pass:

```text
3c1ffc4 Add AI-agent prompt injection checks
```

## Downloaded Raw Corpora

Raw corpora are ignored and live under `data/corpora/`.

| Corpus | Remote path | Status |
| --- | --- | --- |
| Nazario phishing corpus | `data/corpora/nazario` | Downloaded |
| Enron email corpus | `data/corpora/enron` | Downloaded |
| SpamAssassin public corpus | `data/corpora/spamassassin` | Downloaded |
| LLMail-Inject | `data/corpora/huggingface/microsoft__llmail-inject-challenge` | Downloaded |
| Seven Phishing/Spam Email Datasets | `data/corpora/huggingface/puyang2025__seven-phishing-email-datasets` | Downloaded |
| Lakera MOSSCap prompt injection | `data/corpora/huggingface/Lakera__mosscap_prompt_injection` | Downloaded |

Approximate raw corpus size after these downloads: `5.4G`.

## Prepared PhishAnalyze Corpora

### Stable 500-Sample Slice

Path:

```bash
data/eval_corpus
```

This folder is a deterministic evaluation/training slice, not the full corpus.
It was regenerated with `--clean-output`, so the folder contents were replaced,
but the raw corpora were not deleted.

Counts:

| Label | Count |
| --- | ---: |
| `PHISHING` | 200 |
| `CLEAN` | 300 |

Sources:

| Source | Count |
| --- | ---: |
| Nazario phishing | 200 |
| Enron ham | 200 |
| SpamAssassin ham | 100 |

### Full No-Oversample Corpus

Path:

```bash
data/eval_corpus_full_no_oversample
```

This folder uses every available candidate the current preparer can read from
the downloaded Nazario, Enron sent-mail, and SpamAssassin ham corpora. It does
not duplicate rows to balance classes.

Counts:

| Label | Count |
| --- | ---: |
| `PHISHING` | 12,009 |
| `CLEAN` | 130,476 |
| Total | 142,485 |

Sources:

| Source | Available and written |
| --- | ---: |
| Nazario phishing | 12,009 |
| Enron ham | 126,326 |
| SpamAssassin ham | 4,150 |

## Latest PayShield Training

Path:

```bash
models/payment_classifier
```

Dataset:

```bash
data/payment_scam_dataset
```

Rows:

| Split | Count |
| --- | ---: |
| Train | 192 |
| Validation | 25 |
| Test | 26 |
| Holdout | 16 |

Classes:

```text
DO_NOT_PAY, SAFE, VERIFY
```

Latest metrics:

| Metric | Value |
| --- | ---: |
| Test accuracy | 1.000 |
| Holdout accuracy | 1.000 |

Important caveat: the dataset is still small and partly synthetic. Treat this
as a pipeline/readiness result, not a public product-quality claim.

## Prompt-Injection Lane

Both products use the shared `agent_prompt_injection` analyzer. Prompt-injection
datasets should be used to test hostile-input handling for both products.

Do not merge prompt injection into PayShield's payment decision labels unless
the sample is payment-specific. For non-payment prompt-injection emails,
PayShield should surface the AI instruction safety signal without pretending it
is an invoice fraud case.

For PhishAnalyze, prompt-injection emails can be evaluated as suspicious hostile
input, but the LLM or ML model must not become the sole verdict authority.

