#!/bin/bash
set -e
git fetch --tags
latest_tag=$(git tag --sort=-v:refname | grep "^v" | head -n1)
echo "Latest tag: $latest_tag"
numeric_tag=$(echo $latest_tag | sed "s/^v//")
major=$(echo $numeric_tag | cut -d. -f1)
minor=$(echo $numeric_tag | cut -d. -f2)
patch=$(echo $numeric_tag | cut -d. -f3)
case "$1" in
	patch) new_patch=$((patch + 1)); new_tag="v$major.$minor.$new_patch" ;;
	minor) new_minor=$((minor + 1)); new_tag="v$major.$new_minor.0" ;;
	major) new_major=$((major + 1)); new_tag="v$new_major.0.0" ;;
esac
echo "New tag: $new_tag"
git tag $new_tag
