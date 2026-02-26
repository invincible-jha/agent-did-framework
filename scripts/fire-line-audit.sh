#!/usr/bin/env bash
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
#
# fire-line-audit.sh
#
# Scans src/ and examples/ for forbidden AumOS-proprietary identifiers.
# Exits 1 if any match is found.
#
# Run in CI or as a pre-push hook:
#   bash scripts/fire-line-audit.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PATTERN="progressLevel|promoteLevel|computeTrustScore|behavioralScore|adaptiveBudget|optimizeBudget|predictSpending|detectAnomaly|generateCounterfactual|PersonalWorldModel|MissionAlignment|SocialTrust|CognitiveLoop|AttentionFilter|GOVERNANCE_PIPELINE"

SCAN_DIRS=()
if [[ -d "${REPO_ROOT}/src" ]]; then
  SCAN_DIRS+=("${REPO_ROOT}/src")
fi
if [[ -d "${REPO_ROOT}/examples" ]]; then
  SCAN_DIRS+=("${REPO_ROOT}/examples")
fi

if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
  echo "fire-line-audit: no src/ or examples/ directories found — nothing to scan" >&2
  exit 0
fi

echo "fire-line-audit: scanning ${SCAN_DIRS[*]}"

MATCHES=$(grep -rn --include="*.ts" --include="*.js" --include="*.json" -E "${PATTERN}" "${SCAN_DIRS[@]}" 2>/dev/null || true)

if [[ -n "${MATCHES}" ]]; then
  echo ""
  echo "FIRE LINE VIOLATION — forbidden identifier(s) detected:" >&2
  echo ""
  echo "${MATCHES}" >&2
  echo ""
  echo "These identifiers are AumOS-proprietary and must never appear in OSS source." >&2
  echo "See FIRE_LINE.md for the full exclusion list." >&2
  echo ""
  exit 1
fi

echo "fire-line-audit: PASSED — no forbidden identifiers found"
exit 0
