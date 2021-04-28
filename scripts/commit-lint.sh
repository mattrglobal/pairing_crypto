#!/usr/bin/env bash

echo "Linting Git Commits"

set -e

# Pins the version of the commit linter package
CCL_VERSION=0.7.2

# Get the common commit ancestor
COMMON_ANCESTOR_COMMIT=$(git rev-list --parents HEAD | tail -1)

# Install the commit linter
cargo install conventional_commits_linter --version $CCL_VERSION

# Run the linting task
$HOME/.cargo/bin/conventional_commits_linter --from-commit-hash $COMMON_ANCESTOR_COMMIT