# Hyb-Agg Follow-Up — Extension Summary

## The protocol we are extending

Hyb-Agg is our published one-shot secure-aggregation protocol for federated learning on IoT devices. In communication rounds:

- **Setup (once):** the server publishes parameters; clients generate keys and exchange public keys.
- **Each round — one message, client → server:** a client encrypts its update (MK-CKKS) and adds an ECDH-derived pairwise mask, then sends a single payload. The masks cancel when all payloads are summed.
- **Server (same step):** sums the payloads; masks cancel, ciphertexts combine, and it recovers the sum directly — no decryption round.

That single upload is the advantage: comparable schemes (e.g. xMK-CKKS) need a second round to collect decryption shares; Hyb-Agg folds the (masked) share into the upload. **The masking is not incidental — it hides each client's partial-decryption share `μᵢ` from the untrusted server (a bare `μᵢ` would expose that client's input). So masking is the security mechanism, and "improving Hyb-Agg" means improving the masking layer without breaking the share-secrecy it provides.**

## Organizing frame

Four properties — post-quantum, one-shot, verifiable input, dropout resilience — cannot all be had cheaply on constrained hardware. We occupy a named point and characterize the cost of what we don't take (a Pareto-frontier framing).

- **Invariant for every change:** exact correctness (decrypted sum = plaintext sum); no regression on existing guarantees (confidentiality, integrity, N−2 collusion) or on existing costs; new properties may cost, and we measure that cost rather than assume it free.
- **Dropout sub-trilemma:** dropout resilience is itself a three-way pick-two — recovery, one-shot, setup-free. Reconstruction (Shamir) adds a round; threshold decryption needs key setup; exclusion discards the dropped data. So the dropout choice is a genuine trade.

## Directions → candidate solutions 

**1. Cheaper, dropout-tolerant masking (highest leverage — attacks O(N) compute and dropout while keeping share-secrecy).**

- _Sparse mask graph:_ each client masks ~log N neighbours instead of all N−1; masks still cancel; provably secure. Lowest-risk concrete win on client compute.
- _Coded aggregate masks (LightSecAgg-style):_ reconstruct the aggregate mask from already-uploaded shares, so dropout is handled with no per-dropout recovery round. Trade-off to state plainly: this softens literal one-shot to a few rounds (~3 synchronous) and adds client-side encoding cost. Verify first that coded reconstruction composes with MK-CKKS partial-decryption shares (LightSecAgg was built for masks on plaintexts; here the masks sit on the shares).

**2. Full post-quantum (cleanest contribution-per-effort).**

- ML-KEM replaces ECDH for mask-seed derivation (run once at setup to preserve one-shot; also resolves per-round mask freshness).
- ML-DSA replaces classical signatures for authentication and transport.
- Framing: separate the protocol layer (privacy primitives) from the deployment stack (transport, auth, key distribution) — end-to-end PQ needs both, and most work claims only the first.
- Payoff: a fully lattice-based security argument, no classical assumptions. Cost concentrates in setup/storage bytes, negligible per-round.

**3. Payload compression (improves the headline communication metric).**

- CKKS slot packing (group layers/blocks into one plaintext) to push past the ~12× expansion.
- Compatible sparsification (Rand-k or layer-level — not top-k, which breaks aggregation).
- Include a small-payload (adapter-sized) regime in the measurements — broadens the communication story and sets up the LoRA follow-on.
- Coupled to correctness: verify packing keeps noise within the decode budget.

**4. Trusted-setup (CRS) removal (small, verify-then-claim).**

- Per-client public element instead of a shared one; appears viable because Hyb-Agg never forms a true combined multi-key ciphertext. Needs a noise/library check before relying on it.

**5. Input verification (exploratory — cost-vs-utility unknown).**

- Input validation via lattice range proofs (client proves its update is in-range without revealing it) — defends against malicious clients. Heavy on constrained devices; scope modestly and leave Byzantine-robust aggregation as future work. Note: signatures authenticate _who_ sent an update, not that _what_ they sent is well-formed.

## Evaluation plan

_Datasets & utility_

- Real federated-learning tasks (e.g. FEMNIST, Shakespeare, a LoRA fine-tuning task), replacing synthetic data.
- Accuracy parity vs plaintext FedAvg — confirm the privacy machinery doesn't degrade utility.
- Numerical-precision verification — exact aggregate recovery under packing, PQ, and the chosen dropout mechanism.

_Baselines & scaling_

- Reimplemented baselines on matched hardware: SecAgg, LightSecAgg, SASH, xMK-CKKS (+ tMK-CKKS / FedSHE if feasible).
- Scale the number of clients well beyond 500.
- Component ablations isolating each piece (masking variant, PQ, packing).

_Cost (compute / storage / communication)_

- Per-phase wall-clock (keygen, encrypt, mask, aggregate, decode) vs N and vs model dimension d.
- Client and server storage vs N.
- Communication-expansion factor re-measured with packing; include a small/adapter-sized payload point (forward link to LoRA).
- Energy measurement on the Raspberry Pi.

_Mechanism-specific_

- Dropout/churn: dropout-rate sweep; correctness under the chosen mechanism; for coded masks, behaviour at and beyond the pre-set dropout budget.
- Standalone ML-KEM / ML-DSA microbenchmark on the device (sign/verify, encaps/decaps, setup/storage growth vs N).
- Sparse-graph per-client cost vs N (demonstrating O(log N) against the current O(N)).
- Range-proof cost (only if verification is pursued): prover time, proof size, verify time on the Pi.

## Hard tensions (where the proofs get hard)

Worth flagging for anyone joining — these conflicts are where a "combine everything" plan quietly breaks:

- **Verifiability vs privacy** — proving honesty wants per-client artifacts; unlinkable privacy doesn't.
- **Traceability vs privacy** — identifying a bad client needs openable per-client tags, the same linkage that leaks inputs.
- **Recovery vs one-shot vs setup-free** — the dropout sub-trilemma.
- **Post-quantum vs compact aggregation** — BLS aggregates neatly but isn't PQ; ML-DSA is PQ but doesn't aggregate as neatly.

## Out of scope (deliberately excluded)

- **Lattice SNARKs** for ciphertext well-formedness — research-grade, not deployable on a Pi; future-work mention at most.
- **Folding / accumulation** — undercuts one-shot.
- **Machine-checked proofs** — EasyCrypt if ever, not Lean, and only after the pen-and-paper proofs settle.
- **A BLS-based aggregate-signature contribution** — conflicts with the PQ direction.

## Parked / follow-on

- **SaE / mask-free aggregation with cohort-authorized decryption.** A negative result: in individual-key MK-CKKS, exclusion-by-subtraction needs per-client-openable ciphertexts, which leak individual inputs to an untrusted server; share-secrecy therefore forces aggregate-key (xMK-CKKS, which loses subtract-to-exclude on dropout) or threshold decryption (which needs setup). Documents _why_ the masking design is the right choice — design-space analysis, not a candidate protocol.
- **Federated LoRA fine-tuning — the next paper.** Improve the protocol first, then apply it to federated fine-tuning of language models: FFA-LoRA (freeze the A matrix → linear, unbiased aggregation), adapter packing, MKHE composition. Adapters are a tiny fraction of parameters, so communication improves. The gate to settle by measurement: can the target device run the local fine-tuning (hold the frozen base model and train the adapter)? One feasibility test — small base model + adapter on the device, time one step — decides whether it stays in the IoT framing. The small-payload eval point above seeds this.

## The decision that orders everything

**Pin the server threat model (semi-honest vs malicious).** It determines the masking choice, the dropout mechanism, and the post-quantum posture; most downstream forks collapse once it is fixed.