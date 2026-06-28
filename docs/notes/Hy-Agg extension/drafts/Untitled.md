# Hyb-Agg Extension Ideas

**The protocol we are extending.** Hyb-Agg (call it **v1**): MK-CKKS encryption + ECDH-based pairwise masking, giving literal one-shot aggregation — each client sends one payload per round, and the server recovers the sum in a single non-interactive step (decryption fused into the upload). The masking is not incidental: it is what hides each client's partial-decryption share `μᵢ` from the untrusted server (a bare `μᵢ` would expose that client's input). **So masking is the security mechanism, and "improving v1" means improving the masking layer without breaking the share-secrecy it provides.**

**Organizing frame.** Four properties — post-quantum, one-shot, verifiable input, dropout resilience — cannot all be had cheaply on constrained hardware. We occupy a named point and characterize the cost of what we don't take (a Pareto-frontier framing). Invariant for every change: **exact correctness (decrypted sum = plaintext sum); no regression on existing guarantees (confidentiality, integrity, N−2 collusion) or on existing costs; new properties may cost, and we measure that cost rather than assume it free.**

## Directions → candidate solutions

**1. Cheaper, dropout-tolerant masking (highest leverage — attacks O(N) compute + dropout + keeps share-secrecy at once).**

- _Sparse mask graph:_ each client masks with ~log N neighbors instead of all N−1; masks still cancel; provably secure. Lowest-risk concrete win on client compute.
- _Coded aggregate masks (LightSecAgg-style):_ reconstruct the aggregate mask from already-uploaded shares, so dropout is handled with **no recovery round and one-shot preserved** — because masks are coded, not pairwise. This is our dropout answer for v1.

**2. Full post-quantum (cleanest contribution-per-effort).**

- ML-KEM replaces ECDH for mask-seed derivation (run once at setup to preserve one-shot; also fixes per-round mask freshness).
- ML-DSA replaces classical signatures for authentication and transport.
- Payoff: a fully lattice-based security argument, no classical assumptions. Cost concentrates in setup/storage bytes, negligible per-round.

**3. Payload compression (improves the headline communication metric).**

- CKKS slot packing (group layers/blocks into one plaintext) to push past the ~12× expansion.
- Compatible sparsification (Rand-k or layer-level — not top-k, which breaks aggregation).
- Coupled to correctness: must verify packing keeps noise within the decode budget.

**4. Trusted-setup (CRS) removal (small, verify-then-claim).**

- Per-client public element instead of a shared one; appears viable because Hyb-Agg never forms a true combined multi-key ciphertext. Needs a noise/library check before relying on it.

**5. Input verification (exploratory — cost-vs-utility unknown).**

- Input validation via lattice range proofs (client proves its update is in-range without revealing it) — defends against malicious clients. Heavy on constrained devices; scope modestly and leave Byzantine-robust aggregation as future work. Note: signatures authenticate _who_ sent an update, not that _what_ they sent is well-formed.

## Evaluation plan

_Datasets & utility_

- Real federated-learning datasets/tasks (e.g. FEMNIST, Shakespeare, a LoRA fine-tuning task), replacing synthetic data.
- Accuracy parity vs plaintext FedAvg — confirm the privacy machinery does not degrade model utility.
- Numerical-precision verification — confirm exact aggregate recovery (decrypted sum = plaintext sum) still holds under packing, PQ, and the chosen dropout mechanism.

_Baselines & scaling_

- Reimplemented baselines on matched hardware: SecAgg, LightSecAgg, SASH, xMK-CKKS (+ tMK-CKKS / FedSHE if feasible).
- Scale the number of clients well beyond 500.
- Component ablations isolating the contribution of each piece (masking variant, PQ, packing).

_Cost measurement (compute / storage / communication)_

- Per-phase wall-clock (keygen, encrypt, mask, aggregate, decode) vs N and vs model dimension d.
- Client and server storage vs N.
- Communication-expansion factor re-measured with packing (extend the ~12× analysis).
- Energy measurement on resource-constrained devices (Raspberry Pi).

_Mechanism-specific_

- Dropout/churn experiments: dropout-rate sweep; confirm correctness under the chosen mechanism; for coded masks, verify behaviour at and beyond the pre-set dropout budget.
- Standalone ML-KEM / ML-DSA microbenchmark on the constrained device (sign/verify, encaps/decaps, setup byte and storage blow-up vs N).
- Sparse-graph: per-client cost vs N, demonstrating O(log N) vs the current O(N).
- Cohort-auth (only if v2 is ever explored): liveness/latency of the beacon or committee step.
- Range-proof cost (only if input verification is pursued): prover time, proof size, verify time on the Pi — tested against the lightweight claim.

## Parked / follow-on (not concrete; explore only if time)

- **SaE / mask-free aggregation with cohort-authorized decryption (v2).** Set aside as a **negative result**: in individual-key MK-CKKS, exclusion-by-subtraction needs per-client-openable ciphertexts, which leak individual inputs to an untrusted server; share-secrecy therefore forces aggregate-key (xMK-CKKS, which loses subtract-to-exclude on dropout) or threshold decryption (which needs setup). Documents _why_ v1's masking is the right choice — useful as design-space analysis, not as a candidate protocol.
- **LoRA / federated fine-tuning of language models.** Likely the _next_ paper rather than this extension. Candidate pieces: FFA-LoRA (freeze the A matrix → aggregation stays linear and unbiased), BatchCrypt-style packing for the payload, and MKHE composition. Open question that gates it: does the target device class still match Hyb-Agg's bandwidth/energy-constrained IoT framing, or does LLM fine-tuning imply more capable hardware (a scope-coherence tension with the current niche)?

## The decision that orders everything

**Pin the server threat model (semi-honest vs malicious).** It determines the masking choice, the dropout mechanism, and the post-quantum posture; most downstream forks collapse once it is fixed.