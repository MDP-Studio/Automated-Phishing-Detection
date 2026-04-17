#!/usr/bin/env bash
# =============================================================================
# Download all training/evaluation corpora for the ML pipeline.
#
# Run from the project root:
#   chmod +x scripts/download_corpora.sh
#   ./scripts/download_corpora.sh
#
# Downloads go into data/corpora/ inside the project directory.
# Total download size: ~2.1GB (mostly Enron).
# Extracted size: ~3-4GB.
#
# Structure after running:
#   data/corpora/
#     nazario/              <- phishing emails (mbox files, 2005-2025)
#     enron/                <- ham emails (maildir format)
#     spamassassin/         <- ham + spam (individual message files)
#     README.md             <- what's in each folder
# =============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORPORA_DIR="$PROJECT_ROOT/data/corpora"

echo "=== Corpus Downloader ==="
echo "Project root: $PROJECT_ROOT"
echo "Corpora dir:  $CORPORA_DIR"
echo ""

mkdir -p "$CORPORA_DIR"/{nazario,enron,spamassassin}

# ---------------------------------------------------------------------------
# 1. Nazario Phishing Corpus (all years)
#    https://monkey.org/~jose/phishing/
#    ~100MB total across all files
# ---------------------------------------------------------------------------
echo "--- [1/3] Nazario Phishing Corpus ---"
NAZARIO_BASE="https://monkey.org/~jose/phishing"
NAZARIO_DIR="$CORPORA_DIR/nazario"

NAZARIO_FILES=(
    # Legacy mbox files
    "20051114.mbox"
    "phishing0.mbox"
    "phishing1.mbox"
    "phishing2.mbox"
    "phishing3.mbox"
    # Yearly collections (2015-2025)
    "phishing-2015"
    "phishing-2016"
    "phishing-2017"
    "phishing-2018"
    "phishing-2019"
    "phishing-2020"
    "phishing-2021"
    "phishing-2022"
    "phishing-2023"
    "phishing-2024"
    "phishing-2025"
    # Metadata
    "LICENSE.txt"
    "README.txt"
)

for f in "${NAZARIO_FILES[@]}"; do
    if [ -f "$NAZARIO_DIR/$f" ]; then
        echo "  [skip] $f (already exists)"
    else
        echo "  [download] $f"
        wget -q --show-progress -O "$NAZARIO_DIR/$f" "$NAZARIO_BASE/$f" || {
            echo "  [WARN] Failed to download $f -- skipping"
            rm -f "$NAZARIO_DIR/$f"
        }
    fi
done

wget -q --show-progress -O "$NAZARIO_DIR/private-phishing4.mbox" "$NAZARIO_BASE/private-phishing4.mbox"

echo ""

# ---------------------------------------------------------------------------
# 2. Enron Email Dataset (May 7, 2015 version)
#    https://www.cs.cmu.edu/~enron/
#    ~1.7GB compressed, ~3GB extracted
# ---------------------------------------------------------------------------
echo "--- [2/3] Enron Email Dataset ---"
ENRON_DIR="$CORPORA_DIR/enron"
ENRON_TARBALL="$CORPORA_DIR/enron_mail_20150507.tar.gz"
ENRON_URL="https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"

if [ -d "$ENRON_DIR/maildir" ]; then
    echo "  [skip] Already extracted (maildir/ exists)"
else
    if [ ! -f "$ENRON_TARBALL" ]; then
        echo "  [download] enron_mail_20150507.tar.gz (~1.7GB, this will take a while)"
        wget -q --show-progress -O "$ENRON_TARBALL" "$ENRON_URL"
    else
        echo "  [skip] Tarball already downloaded"
    fi
    echo "  [extract] Extracting to $ENRON_DIR/ ..."
    tar xzf "$ENRON_TARBALL" -C "$ENRON_DIR" --strip-components=1
    echo "  [cleanup] Removing tarball to save disk space"
    rm -f "$ENRON_TARBALL"
fi

echo ""

# ---------------------------------------------------------------------------
# 3. SpamAssassin Public Corpus
#    https://spamassassin.apache.org/old/publiccorpus/
#    ~25MB total compressed
# ---------------------------------------------------------------------------
echo "--- [3/3] SpamAssassin Public Corpus ---"
SA_BASE="https://spamassassin.apache.org/old/publiccorpus"
SA_DIR="$CORPORA_DIR/spamassassin"

SA_FILES=(
    # Ham (legitimate email)
    "20030228_easy_ham.tar.bz2"
    "20030228_easy_ham_2.tar.bz2"
    "20030228_hard_ham.tar.bz2"
    # Spam
    "20030228_spam.tar.bz2"
    "20030228_spam_2.tar.bz2"
    "20050311_spam_2.tar.bz2"
)

for f in "${SA_FILES[@]}"; do
    EXTRACTED_NAME="${f%.tar.bz2}"
    # The tarballs extract to folder names like "easy_ham", "spam_2", etc.
    if ls "$SA_DIR"/*/ >/dev/null 2>&1; then
        # Check if any extracted folders exist -- crude but works
        :
    fi
    if [ ! -f "$SA_DIR/$f" ]; then
        echo "  [download] $f"
        wget -q --show-progress -O "$SA_DIR/$f" "$SA_BASE/$f" || {
            echo "  [WARN] Failed to download $f -- skipping"
            rm -f "$SA_DIR/$f"
            continue
        }
    else
        echo "  [skip] $f (already exists)"
    fi
    echo "  [extract] $f"
    tar xjf "$SA_DIR/$f" -C "$SA_DIR"
    rm -f "$SA_DIR/$f"
done

echo ""

# ---------------------------------------------------------------------------
# Write a README describing the corpus structure
# ---------------------------------------------------------------------------
cat > "$CORPORA_DIR/README.md" << 'CORPUS_README'
# Training and Evaluation Corpora

Downloaded by `scripts/download_corpora.sh`.

## nazario/

Jose Nazario's phishing email corpus. Mbox format.
- `phishing0.mbox` through `phishing3.mbox`: legacy collections (2005-2007)
- `20051114.mbox`: November 2005 snapshot
- `phishing-2015` through `phishing-2025`: yearly collections
- Source: https://monkey.org/~jose/phishing/
- License: see LICENSE.txt in the folder

**Use for:** phishing training data, phishing side of stable eval corpus.

## enron/

Enron email dataset (May 7, 2015 version). Maildir format.
- ~150 users, mostly senior management
- ~500K messages total
- `maildir/<username>/sent/` and `maildir/<username>/sent_items/` are
  known-ham (the sender is the Enron employee)
- Source: https://www.cs.cmu.edu/~enron/
- Released by FERC, cleaned by SRI (Melinda Gervasio et al.)

**Use for:** ham training data, ham side of stable eval corpus.
**Use sent/ folders only** for clean ham labels.

## spamassassin/

Apache SpamAssassin public corpus.
- `easy_ham/`, `easy_ham_2/`: clearly legitimate email
- `hard_ham/`: legitimate email that looks spammy
- `spam/`, `spam_2/`: confirmed spam
- Source: https://spamassassin.apache.org/old/publiccorpus/

**Use for:** supplementary training data, augmentation.
CORPUS_README

echo "=== Done ==="
echo ""
echo "Corpus sizes:"
du -sh "$CORPORA_DIR"/nazario/ "$CORPORA_DIR"/enron/ "$CORPORA_DIR"/spamassassin/ 2>/dev/null || true
echo ""
echo "Total:"
du -sh "$CORPORA_DIR" 2>/dev/null || true
echo ""
echo "Next steps:"
echo "  1. Spot-check 50 samples from each corpus for label correctness"
echo "  2. Parse mbox/maildir into structured records (Phase 0)"
echo "  3. Select 500 samples for stable eval corpus"
