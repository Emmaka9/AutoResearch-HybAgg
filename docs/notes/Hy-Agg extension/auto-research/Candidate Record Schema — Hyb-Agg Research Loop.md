

The unit that flows through the loop and lands in the DAG. One record per hypothesis. Fields are grouped by **which brain writes them**, because provenance is what keeps the security gate honest: the `security` block is human-authored by construction and must never be machine-filled.

## Design rules

1. **Provenance is explicit.** Every block records `author` in {human, idea-brain (LLM), search-brain (SkyDiscover), coding-brain (agent), oracle (automatic)}. Nothing downstream trusts a verdict without knowing who wrote it.
2. **Security is a gate, not a metric.** `security.verdict` is binary (pass | fail | unreviewed), human-only, and a `fail` vetoes the candidate regardless of cost. It is never a number and never a training signal.
3. **Correctness AND security gate entry to ranking.** A candidate reaches `cost` ranking only if `correctness.verdict == pass` AND `security.verdict == pass`.
4. **Lineage is first-class.** Every record links to its parent(s) and records what it extends or contradicts. This is what makes the DAG (Flywheel-style) accumulate instead of scatter.

---

## Schema

```yaml
candidate:
  id: cand-0042                      # stable unique id
  created: 2026-06-27T14:00:00Z
  status: unreviewed                 # unreviewed | correctness_failed | security_failed
                                     #            | ranked | accepted | archived_negative
  title: "Coded aggregate masks (LightSecAgg-style) over MK-CKKS shares"

  # -- HYPOTHESIS  (author: human or idea-brain) ---------------------------
  hypothesis:
    author: human                    # human | idea-brain
    mechanism: >
      Replace pairwise mask cancellation with coded aggregate masks: each client
      uploads coded shares; the server reconstructs the COMBINED mask from
      surviving shares, so a dropout needs no per-dropout recovery round.
    targets: [dropout_resilience, compute_cost]   # which property this attacks
    fixed_security_envelope: >       # the structure held INVARIANT during any search
      Masking layer unchanged in kind: r_i remains an unpredictable PRG output
      under CDH/RLWE. Search may vary coding params, NOT the hiding mechanism.
    rationale: >
      Pairwise cancellation orphans terms on dropout; coding the aggregate mask
      removes the orphaning while keeping share-secrecy.
    rules_out_check: >               # guard against re-proposing dead ends
      Not SaE (no mask-free exclusion). Not Shamir-on-seeds (no recovery round).

  # -- PROOF OBLIGATION  (author: human) -----------------------------------
  proof_obligation:
    author: human
    claim: >
      Server (and <= N-2 colluding clients) cannot recover any honest mu_i or x_i.
    reduction_sketch: >
      Indistinguishability of coded shares reduces to PRG security + RLWE; the
      reconstructed combined mask reveals only Sigma, not components.
    threat_model_delta: >            # what changes vs current Hyb-Agg threat model
      None intended. Honest-but-curious server, >=2 honest clients. FLAG if changed.
    open_questions:
      - "Does coded reconstruction compose with MK-CKKS partial-decryption shares?"
    easycrypt_status: not_started    # not_started | obligation_specified | proved

  # -- CORRECTNESS GATE  (author: oracle -- automatic, binary) -------------
  correctness:
    author: oracle
    verdict: pass                    # pass | fail | not_run
    method: "Sigma(c0_i + transformed mu-tilde_i) decode == reference Sigma m_i, exact"
    run_id: run-0042-correctness
    noise_within_budget: true        # CKKS decode-budget check
    dropout_cases_tested: [0, 1, 5, "t_max"]
    notes: "Exact recovery at all tested dropout counts <= budget."

  # -- SECURITY GATE  (author: HUMAN ONLY -- binary veto) ------------------
  # HARD RULE: machine processes may READ this block but MUST NOT WRITE it.
  # verdict stays `unreviewed` until a human signs. A `fail` kills the candidate
  # regardless of cost. This verdict is NEVER fed back as a generation reward.
  security:
    author: human                    # enforced; reject record if author != human
    verdict: unreviewed              # unreviewed | pass | fail
    reviewer: null                   # set on sign-off
    reviewed: null
    threat_model_preserved: null     # true | false
    attack_oracle_result: clean      # OPTIONAL machine pre-screen (refute-only):
                                     #   clean | broke  -- flags OBVIOUS breaks
                                     #   (differencing, collusion<=N-2, residual leak).
                                     #   `clean` does NOT imply secure; `broke`
                                     #   auto-fails. Advisory input to the human only.
    human_notes: ""                  # the actual reasoning; required on pass/fail

  # -- COST  (authors: search-brain + oracle -- continuous, ranked) --------
  # Only meaningful once correctness==pass AND security==pass.
  cost:
    author: [search-brain, oracle]
    measured_on: "Raspberry Pi 4"
    client_compute_ms: null
    server_compute_ms: null
    comm_bytes_per_client: null
    expansion_factor: null           # vs plaintext (current baseline ~12x)
    rounds: null                     # literal one-shot == 1; coded masks ~3
    energy_j: null
    search_provenance: >             # if search-brain optimized params:
      SkyDiscover run skd-0042: optimized coding redundancy vs dropout budget;
      objective = comm_bytes; constraint = exact correctness + fixed envelope.

  # -- IMPLEMENTATION  (author: coding-brain) ------------------------------
  implementation:
    author: coding-brain
    repo_ref: "branch cand-0042"
    openfhe_rag_used: true           # FHE-API grounding (TFHE-Coder lesson)
    human_reviewed_crypto_lines: false   # MUST be true before security pass
    build_passes: true
    tests_pass: true

  # -- LINEAGE  (author: human or loop) ------------------------------------
  lineage:
    parents: [cand-0007]             # what this extends
    extends: "cand-0007 sparse-graph: adds coded recovery on top"
    contradicts: []                  # results this challenges
    supersedes: []
    related_negative: [cand-0031]    # e.g. SaE -- why this avoids that failure

  # -- DECISION  (author: human) -------------------------------------------
  decision:
    author: human
    outcome: pending                 # pending | promote | park | reject
    notes: ""
```

---

## Gate logic (how status moves)

```
unreviewed
   |  correctness.verdict == fail --------------> correctness_failed (archive w/ lineage)
   |  correctness.verdict == pass
   v
[security gate -- HUMAN]
   |  attack_oracle_result == broke ------------> security_failed (auto, advisory->veto)
   |  human verdict == fail --------------------> security_failed (archive w/ lineage)
   |  human verdict == pass
   v
ranked  (now cost vector is meaningful; Pareto against other survivors)
   |
   v
decision: promote -> accepted   |  park -> archived_negative  |  reject -> archived_negative
```

Every terminal state writes back to the DAG with its lineage, so a later candidate's `rules_out_check` and `related_negative` can see why earlier ones died. Negative results are nodes, not deletions.

## Provenance enforcement (the one rule that matters)

- The pipeline **rejects any record** where `security.author != human` or where `security.verdict` was written by a non-human process.
- `attack_oracle_result` is the _only_ machine input allowed near the security block, and it can only **refute** (flag a break), never **certify** (`clean` != secure).
- `cost` ranking code **must not read** `security.verdict` as an input to any score. Security gates entry; it does not weight the objective.

This is what stops the failure mode: the search optimizes cost, the human owns security, and the architecture makes "optimize against the security verdict" structurally impossible rather than merely discouraged.