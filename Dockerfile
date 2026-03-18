# CertiClaw Artifact — Reproducible Build
#
# Build:  docker build -t certiclaw .
# Run:    docker run --rm certiclaw
#
# This builds and validates the full artifact:
#   - OCaml unit tests (75 tests)
#   - Evaluation corpus (29 cases)
#   - Lean 4 proofs (18 theorems)

FROM ocaml/opam:ubuntu-24.04-ocaml-5.3 AS ocaml-base
USER opam
WORKDIR /home/opam/certiclaw

# Install OCaml dependencies
RUN opam install yojson -y

# Copy OCaml sources
COPY --chown=opam:opam dune-project .
COPY --chown=opam:opam lib/ lib/
COPY --chown=opam:opam test/ test/
COPY --chown=opam:opam eval/ eval/
COPY --chown=opam:opam bin/ bin/
COPY --chown=opam:opam examples/ examples/

# Build and test OCaml
RUN eval $(opam env) && dune build
RUN eval $(opam env) && dune exec test/tests.exe
RUN eval $(opam env) && dune exec eval/run_eval.exe

# --- Lean stage (optional, requires elan) ---
FROM ghcr.io/leanprover/lean4:v4.28.0 AS lean-base
WORKDIR /certiclaw/formal

COPY formal/lakefile.toml .
COPY formal/lean-toolchain .
COPY formal/lake-manifest.json .
COPY formal/CertiClaw.lean .
COPY formal/CertiClaw/ CertiClaw/

RUN lake build

# --- Final validation report ---
FROM ocaml/opam:ubuntu-24.04-ocaml-5.3
USER opam
WORKDIR /home/opam/certiclaw

RUN opam install yojson -y

COPY --chown=opam:opam . .

CMD ["bash", "-c", "eval $(opam env) && echo '=== OCaml Tests ===' && dune build && dune exec test/tests.exe && echo '' && echo '=== Evaluation ===' && dune exec eval/run_eval.exe && echo '' && echo '=== All checks passed ==='"]
