# Why temperature=1 silently destroyed our test metrics for three cycles

## TL;DR

A phishing-detection pipeline I'd been maintaining for several months claimed ~90% recall on a curated 22-sample test set. The number had been stable, the test set had been stable, the code hadn't changed for the analyzers that mattered. Then one day the same `python -m pytest` call showed 100% recall, and the next day 80%. Same code, same samples, same machine.

The bug was four characters in a configuration file: `temperature=1` in the LLM client wrapper for the NLP intent analyzer. I'd left the LLM at its default sampling temperature, which meant that a high-confidence phishing email could come back classified as `legitimate` on one run and `credential_harvesting` on the next, depending on which token the model happened to sample first. The "recall" number was sampling noise dressed as a metric.

I caught it by running the same input twice and getting different verdicts. The fix was one line. The lesson took longer.

---

## What actually happened

The `nlp_intent` analyzer uses an LLM to classify email intent into seven categories: credential harvesting, malware delivery, BEC wire fraud, gift card scam, extortion, legitimate, unknown. The LLM call sat inside a thin client wrapper:

```python
async def analyze(self, prompt: str) -> str:
    message = await self._client.messages.create(
        model=self.model,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text
```

Notice what's not there: no `temperature`, no `top_p`. The Anthropic SDK defaults to `temperature=1.0` if you don't specify, which means every call is fully sampled. The same prompt produces a probability distribution over response tokens, and the SDK rolls the dice each time.

For a classification task, this means the answer is non-deterministic across runs. For a *test suite* that uses the classification result as ground truth, this means your assertions are testing the model's confidence margin, not the code's correctness.

The damage was subtle because the model's confidence margin was usually wide enough to mask the issue. On obvious inputs the LLM picks the right label 95% of the time and a near-miss 5% — the test passes most days, fails occasionally, and the failure looks like a flake. The variance only shows up on the *interesting* emails, the ones near the decision boundary, which is exactly the population the test set was designed to stress.

So the test suite was telling me: "your detection works on easy cases (which you didn't need a test for) and is unreliable on hard cases (which is the entire reason the test set exists)."

---

## How I caught it

I ran the same email through the pipeline twice in quick succession while debugging an unrelated issue. The two runs produced different verdicts — one CLEAN, one SUSPICIOUS — and I assumed I'd accidentally changed something between runs. I hadn't. The third run gave a third verdict.

The thing that flipped me from "annoying flake" to "actual bug" was reading the analyzer reasoning string. On run 1 the reasoning said "User is asking about gift cards which is a known social engineering pattern". On run 2 the reasoning said "Email is a routine corporate notification". The LLM was generating substantively different *narratives* for the same input. That's not flakiness in the test harness; that's the model picking different hypotheses each time.

I added a `temperature=0` to the SDK call and the variance went away. The 22 sample test set stabilized. The recall number became reproducible.

---

## What I should have done from day one

`temperature=0` is the correct default for any classification or extraction task that runs through automated tests. The reasoning is:

1. **A test that produces different results on different runs of the same input is not a test.** It's a sampler. Tests need to assert deterministic properties of the code under test, not "the code's behavior is approximately what we expected on average".

2. **`temperature=0` plus `top_p=1` is the actual deterministic configuration**, not just `temperature=0` alone. `temperature=0` means "pick the highest-probability token"; `top_p<1` restricts the candidate set via nucleus sampling, and edge cases in that restriction can still produce token-level variance. Pin both or you don't have determinism, just the appearance of it.

3. **The model version itself is a hidden parameter**, and you have to capture it per-call. LLM providers ship point releases under the same model alias — Anthropic's `claude-haiku-4-5` routes to `claude-haiku-4-5-20251001` today and will route to `claude-haiku-4-5-20260101` after the next release without your code changing. When your test suite starts failing six months from now, you need to tell the difference between "my code regressed" and "the model behind the alias changed". Capture the model ID the API actually used (from `message.model` on the response object) and store it on every result.

The code that finally shipped looks like this:

```python
class LLMResponse(NamedTuple):
    text: str
    model_id: str

async def analyze(self, prompt: str) -> LLMResponse:
    message = await self._client.messages.create(
        model=self.model,
        max_tokens=512,
        temperature=0,  # deterministic: same input -> same output
        top_p=1,        # nucleus sampling disabled (with temperature=0
                        # this keeps generation fully greedy)
        messages=[{"role": "user", "content": prompt}],
    )
    text = message.content[0].text
    model_id = getattr(message, "model", None) or self.model
    return LLMResponse(text=text, model_id=model_id)
```

Three lines that should have been there from the start. The `model_id` field gets threaded through into the analysis result so it shows up in JSON output and the eval harness can detect drift after the fact.

---

## Why it took me three months to notice

The test set was small (22 samples). The variance was masked by the model's confidence margin on easy samples. The "flake" hypothesis was easier to believe than the "non-determinism" hypothesis because I'd always assumed temperature was 0 by default. **It wasn't.**

There's a meta-lesson here about defaults. SDK defaults for sampling parameters are reasonable for *interactive* use cases (chatbots, demos, exploratory coding). They are wrong for *automated* use cases (classifiers, extractors, anything in a CI pipeline). If you're writing the automated kind, you have to override the defaults explicitly, every time, and the absence of the override is itself a bug.

---

## What I check now in any LLM-backed code

Before shipping an LLM call that feeds an automated decision:

- [ ] `temperature=0` set explicitly
- [ ] `top_p=1` set explicitly
- [ ] Model ID captured from the response object, not the request, and stored alongside the result
- [ ] At least one test that runs the same input twice and asserts identical output
- [ ] Documentation noting which fields of the result depend on the LLM (so a future reader knows where to look when verdicts drift)

The first two are five characters and you've already paid the API cost to learn them once. The third is one line and pays for itself the first time a model alias rolls. The fourth catches you the day you forget the first two. The fifth is the thing future-you will thank present-you for.

