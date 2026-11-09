.PHONY: help install test serve demo redteam smoke docker-build docker-run clean

PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

help:  ## list the targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-13s %s\n", $$1, $$2}'

install:  ## create .venv and install Tollgate with the test tools
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

test:  ## run the test suite (offline, a few seconds)
	$(BIN)/pytest -q

serve:  ## run the API and dashboard on http://127.0.0.1:8000
	$(BIN)/tollgate serve

demo:  ## replay six scripted agent scenes against a private in-process server
	$(BIN)/tollgate demo

redteam:  ## replay the 26-scenario attack suite and print the scorecard
	$(BIN)/tollgate redteam

smoke:  ## check your PayPal sandbox keys with a real $1.00 sandbox order (needs .env)
	$(BIN)/tollgate smoke

docker-build:  ## build the container image
	docker build -t tollgate .

docker-run:  ## run the container on http://localhost:8000 (mock payments unless .env has keys)
	docker run --rm -p 8000:8000 --env-file .env tollgate

clean:  ## remove build output and local databases
	rm -rf build dist .pytest_cache *.egg-info src/*.egg-info *.db
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
