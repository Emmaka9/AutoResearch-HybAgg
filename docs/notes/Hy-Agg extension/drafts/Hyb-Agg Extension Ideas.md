## Background: what Hyb-Agg is

Hyb-Agg is a secure-aggregation protocol for federated learning (FL) on resource-constrained (IoT) devices. In FL, many clients train a shared model locally and send only model updates to a server, which aggregates them; _secure_ aggregation ensures the server learns only the **sum** of updates, never any individual client's update.

The design has three parts:

- **MK-CKKS** (multi-key CKKS homomorphic encryption) — clients encrypt updates under their own keys; the scheme supports homomorphic addition across different keys.
- **ECDH-based pairwise masking** — each pair of clients derives a shared mask via Diffie–Hellman; the masks cancel when all updates are summed.
- **Literal one-shot aggregation** — each client sends a single payload per round, and the server recovers the aggregate in one non-interactive step: decryption is fused into the upload, with no separate decryption round. This is the main advantage over comparable schemes (e.g. xMK-CKKS), which need an extra round.

One structural fact shapes every direction below: **the masking is load-bearing for privacy.** Each client's payload contains a partial-decryption share, and a bare share would let the untrusted server recover that client's own update. The mask is what hides it. So "improving Hyb-Agg" means improving the masking layer _without_ losing the privacy it provides.

## Organizing frame

Four properties are all desirable but cannot all be achieved cheaply at once on constrained hardware: **post-quantum security**, **one-shot (non-interactive) aggregation**, **verifiable input**, and **dropout resilience**. The cleanest framing is to treat this as a design frontier — choose a coherent point on it, and characterize the cost of the properties not taken.

Invariant for any change: exact correctness (decrypted sum = plaintext sum); no regression on existing guarantees (confidentiality, integrity, collusion resistance) or existing costs; new properties may add cost, which we _measure_ rather than assume away.

A sharper sub-result on one axis: **dropout resilience is itself a three-way tension — recovery, one-shot, and setup-freeness; pick two.** Reconstructing a dropped client's contribution (recovery) while keeping a single non-interactive round (one-shot) and avoiding extra key setup (setup-free) cannot all hold at once. Shamir-style reconstruction keeps recovery and setup-freeness but adds a round; threshold decryption keeps recovery and one-shot but needs key setup; exclusion-based handling keeps one-shot and setup-freeness but discards the dropped data (robustness, not recovery). This is why the dropout choice in Direction 1 is a genuine trade, not a free pick.

## Research directions

### 1. Cheaper, dropout-tolerant masking _(highest value)_

The current pairwise masking costs each client work proportional to the number of clients (O(N)) and breaks under dropout — a missing client orphans its mask terms, so the remaining masks no longer cancel, corrupting the sum. Two candidate replacements attack compute _and_ dropout while preserving privacy:

- **Sparse mask graph** — each client masks with ~log N neighbours instead of all N−1. Masks still cancel; provably secure; cuts client compute. Lowest-risk concrete improvement.
- **Coded aggregate masks (LightSecAgg-style)** — reconstruct the _aggregate_ mask from already-uploaded shares, so dropouts are handled with no recovery round. Trade-offs to state honestly: this softens "literal one-shot" to a small fixed number of rounds (~3 in synchronous settings); it adds client-side encoding compute; and it uses a _pre-set_ dropout budget (exceed it in a round and reconstruction fails). To verify before committing: that the coded reconstruction composes cleanly with MK-CKKS partial-decryption shares — LightSecAgg was designed for masks on plaintexts, whereas here the masks sit on the decryption shares.

### 2. Full post-quantum security

Currently only half post-quantum: MK-CKKS is lattice-based (quantum-safe), but ECDH masking is not (broken by a quantum attacker). Make it end-to-end:

- **ML-KEM** replaces ECDH for deriving mask seeds. ML-KEM is directional where ECDH is not, so run it once at setup (one encapsulation per pair, carried on the existing key-distribution channel) to preserve one-shot. This also resolves per-round mask freshness.
- **ML-DSA** replaces classical signatures for authentication and transport.
- Useful framing: separate the _protocol layer_ (the aggregation's privacy primitives) from the _deployment stack_ (transport, auth, key distribution). End-to-end PQ requires both; most work claims only the first.
- Payoff: a fully lattice-based security argument with no classical assumptions; the cost concentrates in setup/storage bytes, with negligible per-round and compute overhead.

### 3. Payload compression _(communication cost)_

The protocol expands ciphertext ~12× over plaintext. Reduce it:

- **CKKS slot packing** — group multiple layers/blocks into one plaintext to amortise fixed overhead.
- **Compatible sparsification** — Rand-k or layer-level (not top-k, which breaks the aggregation model).
- Include a **small-payload regime** in the measurements (adapter-sized updates), which broadens the communication story and sets up the LoRA direction below.
- Coupled to correctness: confirm packing keeps noise within the decode budget.

### 4. Trusted-setup (CRS) removal

Possibly removable with a near-one-line change — each client samples its own public element instead of a shared one — because Hyb-Agg never forms a true combined multi-key ciphertext. A trust-assumption improvement; needs a noise and library check before relying on it.

### 5. Input verification _(exploratory)_

Defends against a malicious client submitting a malformed or out-of-range update that silently corrupts the aggregate. The honest path is lattice range proofs (prove an update is in-range without revealing it), but these are heavy on constrained devices — so scope modestly (input validation only) and leave full Byzantine-robust aggregation as future work. Note: signatures authenticate _who_ sent an update, not that _what_ they sent is well-formed; they do not substitute for this.

### 6. Application: federated LoRA / fine-tuning

A larger application direction. Instead of aggregating full model updates, aggregate low-rank **LoRA adapters** from federated fine-tuning of language models. Candidate pieces: **FFA-LoRA** (freeze the A matrix so aggregation stays linear and unbiased), **adapter packing**, and **MKHE composition**. Adapters are a small fraction of model parameters, so the payload — and the communication cost — _shrinks_, which strengthens the protocol's headline story rather than straining it.

The gating question, to resolve by measurement: can the target constrained device _locally run_ the fine-tuning — hold the frozen base model and train the adapter? If yes, this is a strong direction. If it requires more capable hardware, it changes the device-class framing and should be scoped accordingly. (A single feasibility test — load a small base model with a LoRA adapter on the target device and time one local fine-tuning step — settles this.)

## Design-space note (negative result)

An alternative we examined and set aside, worth documenting as analysis: **mask-free aggregation with cohort-authorized decryption** — drop masking entirely and handle dropout by subtracting excluded clients' ciphertexts. It does _not_ provide privacy against an untrusted server in individual-key MK-CKKS, because each client's ciphertext is independently openable, so releasing decryption shares leaks individual inputs. Share-secrecy therefore requires either an _aggregate-key_ construction (xMK-CKKS, which loses the clean subtract-to-exclude on dropout) or _threshold decryption_ (which needs setup). This explains _why_ the masking-based design is the right choice and clarifies the trade-offs other schemes make — useful as design-space analysis, not as a candidate protocol.

## Tensions to keep in view (where the proofs get hard)

Several pairs of desirable properties are in genuine conflict — these are where formal work is hardest, and where a tempting "combine everything" pitch quietly breaks. Worth flagging for anyone joining the project:

- **Verifiability vs privacy.** Proving the server summed honestly, or that a client's input is well-formed, pushes toward per-client-attributable artifacts; unlinkable privacy pushes the other way.
- **Traceability vs privacy.** Identifying _which_ client sent a bad update (to exclude or audit it) requires openable, retained per-client tags — structurally the same linkage that leaks individual inputs. To point a finger you must keep something openable about each client.
- **Recovery vs one-shot vs setup-free.** The dropout sub-trilemma noted above.
- **Post-quantum vs elegant aggregation.** Compact aggregate-signature constructions (e.g. BLS) are not quantum-safe; the quantum-safe signature (ML-DSA) does not aggregate as neatly. You can have compactness or post-quantum, not both cheaply.

## Out of scope (deliberately excluded)

Ruled out for this line of work, recorded so the reasoning isn't re-derived:

- **Lattice SNARKs** (e.g. LaBRADOR, Greyhound) for proving ciphertext well-formedness — the theoretical "have-everything" object, but research-grade and not deployable on constrained hardware. At most a one-paragraph future-work mention.
- **Folding / accumulation schemes** — amortize proof cost across rounds, but undercut the one-shot property.
- **Machine-checked proofs** — if ever pursued, the right tool is EasyCrypt (built for cryptographic reductions), not Lean, and only after the pen-and-paper proofs are settled. Not on the critical path.
- **A full aggregate-signature contribution built on BLS** — conflicts with the post-quantum direction.

## Evaluation plan

**Datasets & utility**

- Real federated-learning datasets/tasks (e.g. FEMNIST, Shakespeare, a LoRA task), replacing synthetic data.
- Accuracy parity vs plaintext FedAvg.
- Numerical-precision verification — exact aggregate recovery under packing, PQ, and the chosen dropout mechanism.

**Baselines & scaling**

- Reimplemented baselines on matched hardware: SecAgg, LightSecAgg, SASH, xMK-CKKS (and others if feasible).
- Scale the number of clients well beyond 500.
- Component ablations isolating each piece (masking variant, PQ, packing).

**Cost measurement (compute / storage / communication)**

- Per-phase wall-clock (keygen, encrypt, mask, aggregate, decode) vs N and vs model dimension.
- Client and server storage vs N.
- Communication-expansion factor re-measured with packing.
- Energy measurement on the resource-constrained device.

**Mechanism-specific**

- Dropout/churn: rate sweep; correctness under the chosen mechanism; behaviour at and beyond the coded-mask dropout budget.
- Standalone ML-KEM / ML-DSA microbenchmark on the device (sign/verify, encaps/decaps, setup/storage growth vs N).
- Sparse-graph cost vs N (demonstrating O(log N) against the current O(N)).
- Small-payload / adapter-sized point (forward link to the LoRA direction).
- Conditional: range-proof cost on the device (if verification is pursued); cohort-auth liveness (only if the mask-free variant is revisited).

## Open decisions

- **Threat model — semi-honest vs malicious server.** This is the decision that orders everything else: it determines the masking choice, the dropout mechanism, and the post-quantum posture.
- **Scope.** Whether these directions form one work or several is deliberately left open until the threat model and the LoRA-feasibility question are settled.