#!/usr/bin/env bash
# Installs local Git hooks to automatically review outgoing changes before pushing.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_FILE="${REPO_ROOT}/.git/hooks/pre-push"

echo "Installing pre-push Intelligent Code Reviewer hook..."

cat << 'EOF' > "${HOOK_FILE}"
#!/usr/bin/env bash
# Intelligent Code Reviewer Pre-Push Hook
set -e

echo "🔍 Running Intelligent Code Reviewer pre-push security & quality scan..."

# Run the review bot on outgoing commits
if command -v python3 >/dev/null 2>&1; then
    if [ -f "scripts/pr_review_bot.py" ]; then
        python3 scripts/pr_review_bot.py --mode=pre-push
    fi
fi

exit 0
EOF

chmod +x "${HOOK_FILE}"
echo "✅ Successfully installed pre-push hook in .git/hooks/pre-push."
echo "   Your outgoing commits will now be automatically scanned for secrets and defects before git push."

