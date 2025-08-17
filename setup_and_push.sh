#!/bin/bash
set -e

# ================================
# 🚀 Setup & Push to GitHub Script
# ================================

# 1. Create Python virtual environment
echo "[*] Creating virtual environment..."
python3 -m venv .venv

echo "[*] Activating environment..."
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# 2. Initialize Git repository
echo "[*] Initializing Git repository..."
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit: Cloud Compliance Automation Framework (CCAF)"

# 3. Authenticate with GitHub (interactive)
echo "[*] Authenticating with GitHub..."
if ! command -v gh &> /dev/null
then
    echo "[*] GitHub CLI (gh) not found, installing..."
    sudo apt update && sudo apt install gh -y
fi

gh auth login

# 4. Create GitHub repo and push
REPO_NAME="cloud-compliance-framework"
echo "[*] Creating GitHub repo: $REPO_NAME ..."
gh repo create "$REPO_NAME" --public --source=. --remote=origin --push

# 5. Verify remote
echo "[*] Verifying remote..."
git remote -v

echo "✅ Done! Your project is live on GitHub."

