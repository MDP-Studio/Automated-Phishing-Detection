#!/usr/bin/env python3
"""Test all API clients with live keys."""
import asyncio
import os
import json
import sys
import base64

sys.path.insert(0, '.')
from dotenv import load_dotenv
load_dotenv('/sessions/quirky-kind-wozniak/mnt/Automated Phishing Detection/.env')

import aiohttp


async def test_virustotal():
    key = os.getenv('VIRUSTOTAL_API_KEY')
    if not key:
        return "SKIP: no key"

    test_url = "https://www.google.com"
    url_id = base64.urlsafe_b64encode(test_url.encode()).decode().strip("=")

    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": key},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return f"OK (status={resp.status}, stats={json.dumps(stats)})"
            else:
                text = await resp.text()
                return f"FAIL (status={resp.status}, body={text[:200]})"


async def test_urlscan():
    key = os.getenv('URLSCAN_API_KEY')
    if not key:
        return "SKIP: no key"

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://urlscan.io/api/v1/search/?q=domain:google.com&size=1",
            headers={"API-Key": key},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return f"OK (status={resp.status}, results={data.get('total', 0)})"
            else:
                text = await resp.text()
                return f"FAIL (status={resp.status}, body={text[:200]})"


async def test_abuseipdb():
    key = os.getenv('ABUSEIPDB_API_KEY')
    if not key:
        return "SKIP: no key"

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                d = data.get('data', {})
                return f"OK (8.8.8.8: abuse_score={d.get('abuseConfidenceScore')}, isp={d.get('isp')})"
            else:
                text = await resp.text()
                return f"FAIL (status={resp.status}, body={text[:200]})"


async def test_google_safebrowsing():
    key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if not key:
        return "SKIP: no key"

    body = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": "https://www.google.com"}]
        }
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=body,
            timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                matches = data.get('matches', [])
                return f"OK (threats={len(matches)} for google.com — expected 0)"
            else:
                text = await resp.text()
                return f"FAIL (status={resp.status}, body={text[:200]})"


async def test_hybrid_analysis():
    key = os.getenv('HYBRID_ANALYSIS_API_KEY')
    if not key:
        return "SKIP: no key"

    headers = {"api-key": key, "Accept": "application/json", "User-Agent": "Falcon Sandbox"}

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://www.hybrid-analysis.com/api/v2/search/terms",
            headers=headers,
            data={"filename": "test.exe"},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            if resp.status in (200, 404):
                return f"OK (status={resp.status}, key accepted)"
            elif resp.status == 401:
                return "FAIL (invalid API key)"
            else:
                text = await resp.text()
                return f"UNKNOWN (status={resp.status}, body={text[:200]})"


async def test_whois_dns():
    """Test WHOIS + DNS (no API key needed)."""
    try:
        import whois
        w = whois.whois("google.com")
        domain_name = w.domain_name
        registrar = w.registrar
        return f"OK (google.com: registrar={registrar}, domain={domain_name})"
    except ImportError:
        return "SKIP: python-whois not installed"
    except Exception as e:
        return f"FAIL ({type(e).__name__}: {e})"


async def main():
    tests = [
        ("VirusTotal v3", test_virustotal),
        ("urlscan.io", test_urlscan),
        ("AbuseIPDB v2", test_abuseipdb),
        ("Google Safe Browsing v4", test_google_safebrowsing),
        ("Hybrid Analysis", test_hybrid_analysis),
        ("WHOIS/DNS (local)", test_whois_dns),
    ]

    print("=" * 60)
    print("API CLIENT LIVE TESTS")
    print("=" * 60)

    passed = 0
    failed = 0
    skipped = 0

    for name, test_fn in tests:
        try:
            result = await asyncio.wait_for(test_fn(), timeout=20)
            if result.startswith("OK"):
                status = "✓"
                passed += 1
            elif result.startswith("SKIP"):
                status = "—"
                skipped += 1
            else:
                status = "✗"
                failed += 1
            print(f"  {status} {name}: {result}")
        except asyncio.TimeoutError:
            print(f"  ✗ {name}: TIMEOUT (>20s)")
            failed += 1
        except Exception as e:
            print(f"  ✗ {name}: ERROR — {type(e).__name__}: {e}")
            failed += 1

    print(f"\n  Results: {passed} passed, {failed} failed, {skipped} skipped")
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
