
**Framing / contributions **
- Quadrilemma: PQ (P1), one-shot (P2), verifiable input (P3), dropout resilience (P4) — pick a point, cost the rest.
- Sub-result: the dropout axis is its own trilemma (recovery + one-shot + setup-free, pick two).
- Two-layer PQC axis (protocol layer vs deployment stack) as a comparative dimension for related work.

**Design ideas — by axis**

_Spines :_

- #1 Robust + scalable Hyb-Agg (primary).
- #2 End-to-end PQ Hyb-Agg (secondary bolt-on).
- #3 Federated LLM/SLM fine-tuning: FFA-LoRA + BatchCrypt packing + MKHE).

_P1 — post-quantum:_

- KEM-in-setup (ML-KEM once per pair, rides existing O(N) key distribution).
- Per-round PRG nonce/counter mask refresh.
- ML-DSA for auth + key distribution.

_P3 — verifiable input:_

- Input validation: lattice range/norm proofs (‖update‖≤B + well-formedness), client-side, one-shot.
- Verifiable aggregation: server proves honest sum (VerSA/EVFL-style tags) — different threat.

_P4 — dropout (the menu):_

- SaE + cohort-authorization (beacon / attested-roster) — robustness, removes O(N), semi-honest-server only.
- Threshold HE (t-of-n) — recovery, DKG cost.
- Shamir-masked (Bonawitz) — recovery, breaks one-shot (baseline).
- DP-substitute over sparse mask graph — approximate recovery, utility hit.

_Removing O(N) compute:_

- Sparse mask graph (k-regular, O(log N)).
- Seed-homomorphic PRG (SASH-style).
- Drop masking entirely via SaE.

_CRS removal:_

- Per-client `aᵢ` tweak (drop shared-`a`) — verify noise + OpenFHE bundling.

**Experiments**

- Real datasets (FEMNIST / Shakespeare / LoRA task) replacing synthetic.
- Reimplemented baselines, same hardware: SecAgg, LightSecAgg, SASH, xMK-CKKS (+ tMK-CKKS / FedSHE if feasible).
- Scale N well beyond 500.
- Energy measurements on the Pi.
- Client + server wall-clock vs N and vs d, rerun per mechanism.
- Communication expansion (extend the ~12× analysis).
- Dropout robustness: vary dropout rate, measure aggregate correctness.
- SaE-specific: churn experiment quantifying exclusion bias (fairness/representation).
- PQ overhead: ML-KEM setup cost, ML-DSA sign/verify on Pi, key/ciphertext size deltas.
- Range-proof cost (if P3): prover time, proof size, verify time on Pi — test against "lightweight."
- Sparse-graph: per-client cost vs N showing O(log N) vs current O(N).
- Numerical precision: confirm exact aggregation holds with new mechanisms.
- Cohort-auth: liveness/latency of beacon or committee step.


**Open decisions (the gate — anchor the meeting here)**

- Server threat model: semi-honest vs malicious.
- Recovery vs robustness — is exclusion acceptable?
- Keep masking or drop it (SaE)?
- P3 this paper or future work?
- One paper or split #3 into a follow-on?
- Eval resourcing.

**Tensions to keep in view** (where proofs get hard): traceability vs privacy; verifiability vs privacy; recovery vs one-shot vs setup-free; PQ vs elegant aggregation.

**Out of scope** : lattice SNARKs; folding; Lean (EasyCrypt only if ever); full BLS aggregate-sig contribution; "new maths solves all."