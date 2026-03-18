# CertiClaw Artifact — Reproducible OCaml Validation
#
# Build:  docker build -t certiclaw .
# Run:    docker run --rm certiclaw
#
# Validates OCaml tests (75) and evaluation corpus (29 cases).
# Lean proofs are validated separately by CI (see .github/workflows/ci.yml).

FROM ocaml/opam:ubuntu-24.04-ocaml-5.3

USER opam
WORKDIR /home/opam/certiclaw

# Install OCaml dependencies
RUN opam install yojson dune -y

# Copy only what's needed for the OCaml build
COPY --chown=opam:opam dune-project .
COPY --chown=opam:opam lib/ lib/
COPY --chown=opam:opam test/ test/
COPY --chown=opam:opam eval/ eval/
COPY --chown=opam:opam bin/ bin/
COPY --chown=opam:opam examples/ examples/

# Build
RUN eval $(opam env) && dune build

# Default: run full validation
CMD ["bash", "-c", "\
  eval $(opam env) && \
  echo '=== CertiClaw Artifact Validation ===' && echo '' && \
  echo '[1/2] Unit tests (75)...' && \
  dune exec test/tests.exe && echo '' && \
  echo '[2/2] Evaluation corpus (29 cases)...' && \
  dune exec eval/run_eval.exe && echo '' && \
  echo '=== All checks passed ===' \
"]
