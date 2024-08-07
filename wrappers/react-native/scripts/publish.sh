#!/bin/bash

# Fail if any command in script fails
set -e

# This script handles the publishing of the current
# commits as an npm based package

# Example if the current package.json version reads 0.1.0
# then the release will be tagged with 0.1.0

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

# Fetch the current version from the package.json
new_version=$(node -pe "require('./package.json').version")

# Check if the new version is not the current
new_version_exists=$(yarn info '@mattrglobal/pairing-crypto-rn' --json | jq --arg version "$new_version" -r '.data.versions | any(index($version))')

# Version to this new unstable version
if [[ "$new_version_exits" != "true" ]]; then
    yarn publish --no-git-tag-version --new-version $new_version
fi
# Reset changes to the package.json
git checkout -- package.json
