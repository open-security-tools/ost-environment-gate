.PHONY: fmt test build sam-build deploy deploy-secrets

fmt:
	cargo fmt

test:
	cargo test

build:
	cargo lambda build --release --arm64

sam-build:
	sam build --beta-features --no-use-container

deploy:
	./scripts/deploy.sh

deploy-secrets:
	./scripts/deploy-secrets.sh
