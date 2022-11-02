#!/bin/bash

set -e

# This script handles the publishing of the current
# commits as an npm based unstable package

# Example if the current package.json version reads 0.1.0
# then the unstable release of 0.1.1-unstable.(current git commit reference)

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

# Minor version the current package
npm version --git-tag-version=false --patch

# Fetch the current version from the package.json
new_version=$(node -pe "require('./package.json').version")

# Fetch the new unstable version
new_unstable_version=$new_version"-unstable.$(git rev-parse --short HEAD)"

# Version to this new unstable version
#
# Must publish with NPM due to a known bug on Yarn v1 that doesn't support negation
# rules on "files" in the package.json file.
npm version --git-tag-version=false $new_unstable_version
npm publish --tag unstable

# Reset changes to the package.json
git checkout -- package.json
