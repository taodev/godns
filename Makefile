.PHONY: patch minor major

patch:
	@bash scripts/tag.sh patch

minor:
	@bash scripts/tag.sh minor

major:
	@bash scripts/tag.sh major