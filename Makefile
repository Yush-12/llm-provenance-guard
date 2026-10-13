# spanguard — task runner
#
# Requires: GNU Make (available on Windows via Git for Windows / Chocolatey)
#
# Targets
# -------
#   make check    Run ruff, mypy, and pytest in sequence (CI gate).
#   make fmt      Auto-fix ruff formatting and import sorting.
#   make lint     ruff check only (no mypy, faster inner loop).
#   make types    mypy only.
#   make test     pytest only.
#   make clean    Remove build artefacts and caches.

UV      ?= uv
PYTHON  := $(UV) run python
RUFF    := $(UV) run ruff
MYPY    := $(UV) run mypy
PYTEST  := $(UV) run pytest
SRC     := src/spanguard
TESTS   := tests
BENCH   := bench
PROXY   := proxy
ARENA   := arena

.PHONY: check fmt lint types test bench clean install harvest

## install — sync the virtual environment (run once after clone)
install:
	$(UV) sync --extra dev

## check — full CI gate: format-check → lint → types → tests → bench
check: install
	$(RUFF) format --check $(SRC) $(TESTS) $(BENCH) $(PROXY) $(ARENA)
	$(RUFF) check $(SRC) $(TESTS) $(BENCH) $(PROXY) $(ARENA)
	$(MYPY) $(SRC) $(BENCH) $(PROXY) $(ARENA)
	$(PYTEST)
	$(PYTHON) -m bench.runner

## fmt — auto-fix formatting and import order (destructive)
fmt:
	$(RUFF) format $(SRC) $(TESTS) $(BENCH) $(PROXY) $(ARENA)
	$(RUFF) check --fix $(SRC) $(TESTS) $(BENCH) $(PROXY) $(ARENA)

## lint — ruff only (fast loop during development)
lint:
	$(RUFF) check $(SRC) $(TESTS) $(BENCH) $(PROXY) $(ARENA)

## types — mypy only
types:
	$(MYPY) $(SRC) $(BENCH) $(PROXY) $(ARENA)

## test — pytest only
test:
	$(PYTEST)

## bench — run benchmark evaluation suite
bench:
	$(PYTHON) -m bench.runner

## harvest — export level-6-and-above bypass attempts to reviewable file
harvest:
	$(PYTHON) -m arena.harvest

## clean — remove caches and build artefacts
clean:
	rm -rf .mypy_cache .ruff_cache .pytest_cache dist build
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
