#!/usr/bin/env python3
"""
Batch test runner: sends all sample .eml files through the phishing pipeline API
and saves detailed results as JSON for analysis.
"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# Load .env so API keys are available
try:
    from dotenv import load_dotenv
    load_dotenv(project_root / ".env")
except ImportError:
    env_path = project_root / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and not key.startswith("#"):
                    os.environ.setdefault(key, val)

from src.extractors.eml_parser import parse_eml_file
from src.orchestrator.pipeline import PhishingPipeline
from src.config import PipelineConfig


SAMPLES_DIR = Path(__file__).parent
RESULTS_FILE = SAMPLES_DIR / "batch_results.json"

# Expected verdicts for each sample
EXPECTED = {
    "sample_01_microsoft_credential_harvest.eml":  "PHISHING",
    "sample_02_paypal_account_suspension.eml":      "PHISHING",
    "sample_03_dhl_delivery_notification.eml":      "PHISHING",
    "sample_04_apple_id_disabled.eml":              "PHISHING",
    "sample_05_netflix_payment_failed.eml":         "PHISHING",
    "sample_06_bank_of_america_wire_confirm.eml":   "PHISHING",
    "sample_07_amazon_order_confirm.eml":           "PHISHING",
    "sample_08_google_workspace_shared_doc.eml":    "PHISHING",
    "sample_09_irs_tax_refund.eml":                 "PHISHING",
    "sample_10_linkedin_connection_request.eml":    "PHISHING",
    "sample_11_legitimate_github_notification.eml": "CLEAN",
    "sample_12_legitimate_work_email.eml":          "CLEAN",
    # Legitimate brand emails — false positive test
    "sample_13_legitimate_amazon_order.eml":         "CLEAN",
    "sample_14_legitimate_paypal_receipt.eml":       "CLEAN",
    "sample_15_legitimate_google_security_alert.eml":"CLEAN",
    "sample_16_legitimate_netflix_new_show.eml":     "CLEAN",
    "sample_17_legitimate_linkedin_digest.eml":      "CLEAN",
    "sample_18_legitimate_bank_statement.eml":       "CLEAN",
    "sample_19_legitimate_dhl_tracking.eml":         "CLEAN",
    "sample_20_legitimate_stripe_invoice.eml":       "CLEAN",
    "sample_21_legitimate_newsletter.eml":           "CLEAN",
    "sample_22_legitimate_docusign.eml":             "CLEAN",
}


async def analyze_sample(pipeline, eml_path: Path) -> dict:
    """Run a single .eml file through the pipeline and return results."""
    print(f"\n{'='*70}")
    print(f"Analyzing: {eml_path.name}")
    print(f"{'='*70}")

    start = time.time()

    # Parse the .eml file
    email = parse_eml_file(str(eml_path))

    # Run pipeline
    result = await pipeline.analyze(email)

    elapsed = time.time() - start

    # Extract key info — analyzer_results is dict[str, AnalyzerResult]
    analyzer_results = {}
    for name, ar in result.analyzer_results.items():
        details_safe = {}
        if hasattr(ar, 'details') and ar.details:
            for k, v in ar.details.items():
                if isinstance(v, bytes):
                    details_safe[k] = f"<{len(v)} bytes>"
                else:
                    try:
                        json.dumps(v)
                        details_safe[k] = v
                    except (TypeError, ValueError):
                        details_safe[k] = str(v)

        analyzer_results[name] = {
            "risk_score": ar.risk_score if hasattr(ar, 'risk_score') else 0,
            "confidence": ar.confidence if hasattr(ar, 'confidence') else 0,
            "details": details_safe,
        }

    # IOCs — result.iocs is a dict, not an object
    iocs = {}
    if result.iocs and isinstance(result.iocs, dict):
        iocs = {
            "urls": [],
            "domains": [],
            "headers": {},
        }
        if "extracted_urls" in result.iocs:
            for u in result.iocs["extracted_urls"]:
                if hasattr(u, 'url'):
                    iocs["urls"].append(u.url)
                elif isinstance(u, dict):
                    iocs["urls"].append(u.get("url", str(u)))
                else:
                    iocs["urls"].append(str(u))
        if "suspicious_domains" in result.iocs:
            iocs["domains"] = list(result.iocs["suspicious_domains"])
        if "headers" in result.iocs and isinstance(result.iocs["headers"], dict):
            for k, v in result.iocs["headers"].items():
                try:
                    json.dumps(v)
                    iocs["headers"][k] = v
                except (TypeError, ValueError):
                    iocs["headers"][k] = str(v)

    # Also handle extracted_urls at top level
    ext_urls = []
    if result.extracted_urls:
        for u in result.extracted_urls:
            if hasattr(u, 'url'):
                ext_urls.append(u.url)
            elif isinstance(u, dict):
                ext_urls.append(u.get("url", str(u)))
            else:
                ext_urls.append(str(u))
    if ext_urls and not iocs.get("urls"):
        iocs["urls"] = ext_urls

    expected = EXPECTED.get(eml_path.name, "UNKNOWN")
    verdict = str(result.verdict.value) if hasattr(result.verdict, 'value') else str(result.verdict)
    score = result.overall_score

    # Determine if detection was correct
    is_phishing_expected = expected == "PHISHING"
    is_flagged = verdict in ("SUSPICIOUS", "LIKELY_PHISHING", "CONFIRMED_PHISHING")

    if is_phishing_expected:
        detection = "TRUE_POSITIVE" if is_flagged else "FALSE_NEGATIVE"
    else:
        detection = "FALSE_POSITIVE" if is_flagged else "TRUE_NEGATIVE"

    reasoning = result.reasoning
    if isinstance(reasoning, list):
        reasoning = " ".join(reasoning)

    record = {
        "filename": eml_path.name,
        "expected": expected,
        "verdict": verdict,
        "weighted_score": round(score, 4) if score else 0,
        "confidence": round(result.overall_confidence, 4) if result.overall_confidence else 0,
        "detection_result": detection,
        "elapsed_seconds": round(elapsed, 2),
        "from": email.from_address,
        "subject": email.subject,
        "analyzer_results": analyzer_results,
        "iocs": iocs,
        "reasoning": reasoning,
    }

    # Print summary
    status = "✅" if detection in ("TRUE_POSITIVE", "TRUE_NEGATIVE") else "❌"
    print(f"  From:     {email.from_address}")
    print(f"  Subject:  {email.subject}")
    print(f"  Verdict:  {verdict} (score: {score:.1%})")
    print(f"  Expected: {expected}")
    print(f"  Result:   {status} {detection}")
    print(f"  Time:     {elapsed:.1f}s")

    # Print analyzer breakdown
    print(f"  Analyzers:")
    for name, ar in sorted(analyzer_results.items(), key=lambda x: x[1]["risk_score"], reverse=True):
        bar = "█" * int(ar["risk_score"] * 20)
        print(f"    {name:25s} {ar['risk_score']:.0%} {bar} (conf: {ar['confidence']:.0%})")

    return record


async def main():
    print("=" * 70)
    print("PHISHING PIPELINE BATCH TEST")
    print(f"Running {len(EXPECTED)} samples through full analysis pipeline")
    print("=" * 70)

    # Initialize pipeline with env vars (API keys from .env)
    config = PipelineConfig.from_env()
    pipeline = PhishingPipeline(config)

    # Collect sample files
    eml_files = sorted(SAMPLES_DIR.glob("sample_*.eml"))
    print(f"\nFound {len(eml_files)} sample files")

    results = []
    try:
        for eml_path in eml_files:
            try:
                record = await analyze_sample(pipeline, eml_path)
                results.append(record)
            except Exception as e:
                print(f"\n  ❌ ERROR analyzing {eml_path.name}: {e}")
                import traceback
                traceback.print_exc()
                results.append({
                    "filename": eml_path.name,
                    "expected": EXPECTED.get(eml_path.name, "UNKNOWN"),
                    "verdict": "ERROR",
                    "error": str(e),
                    "detection_result": "ERROR",
                })
    finally:
        await pipeline.close()

    # Save results
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str, ensure_ascii=False)
    print(f"\n\nResults saved to: {RESULTS_FILE}")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    tp = sum(1 for r in results if r["detection_result"] == "TRUE_POSITIVE")
    tn = sum(1 for r in results if r["detection_result"] == "TRUE_NEGATIVE")
    fp = sum(1 for r in results if r["detection_result"] == "FALSE_POSITIVE")
    fn = sum(1 for r in results if r["detection_result"] == "FALSE_NEGATIVE")
    errors = sum(1 for r in results if r["detection_result"] == "ERROR")

    total_phishing = sum(1 for r in results if r["expected"] == "PHISHING")
    total_legit = sum(1 for r in results if r["expected"] == "CLEAN")

    print(f"\n  Phishing samples:    {total_phishing}")
    print(f"  Legitimate samples:  {total_legit}")
    print(f"  Errors:              {errors}")
    print(f"\n  True Positives:      {tp}/{total_phishing}")
    print(f"  True Negatives:      {tn}/{total_legit}")
    print(f"  False Positives:     {fp}/{total_legit}")
    print(f"  False Negatives:     {fn}/{total_phishing}")

    if total_phishing > 0:
        detection_rate = tp / total_phishing * 100
        print(f"\n  Detection Rate:      {detection_rate:.0f}%")
    if (tp + fp) > 0:
        precision = tp / (tp + fp) * 100
        print(f"  Precision:           {precision:.0f}%")
    if (tp + fn) > 0:
        recall = tp / (tp + fn) * 100
        print(f"  Recall:              {recall:.0f}%")

    print("\n  Per-sample results:")
    for r in results:
        status = {"TRUE_POSITIVE": "✅ TP", "TRUE_NEGATIVE": "✅ TN", "FALSE_POSITIVE": "❌ FP", "FALSE_NEGATIVE": "❌ FN", "ERROR": "⚠️ ERR"}.get(r["detection_result"], "?")
        score_str = f"{r.get('weighted_score', 0):.0%}" if "weighted_score" in r else "N/A"
        print(f"    {status}  {r['filename']:50s}  verdict={r['verdict']:20s}  score={score_str}")


if __name__ == "__main__":
    asyncio.run(main())
