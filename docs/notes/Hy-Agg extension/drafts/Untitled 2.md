# Hyb-Agg Extension Ideas

## What Hyb-Agg is

Hyb-Agg is our published secure-aggregation protocol for federated learning on IoT devices. In federated learning, clients train a shared model locally and send only their updates to a server, which averages them. Secure aggregation keeps the server from seeing any single update, only the sum.

The protocol runs in one round per training step:

- Setup happens once. The server publishes parameters; clients generate keys and exchange public keys.
- Each step, a client sends a single message: its encrypted update (MK-CKKS) plus an ECDH-derived pairwise mask. The masks are built to cancel once everything is summed.
- The server adds the messages, the masks cancel, and it reads off the summed update. There is no second round.

That single message is what sets Hyb-Agg apart. Other schemes, xMK-CKKS among them, need a second round to gather decryption shares. Hyb-Agg ships that share, masked, inside the first message. The mask does double duty: it also hides each client's share from the server, and without it the server could reconstruct an individual update. So the masking is the security mechanism, not an optimization detail. Improving Hyb-Agg means making the masking cheaper or stronger without losing the privacy it provides.

## The framing

Four properties matter here: post-quantum security, one-shot aggregation, verifiable input, and dropout resilience. On constrained hardware we cannot get all four cheaply. The paper picks a coherent point and reports what the properties it skips would cost.

Two ground rules. First, correctness is fixed: the decrypted sum must equal the plaintext sum, and no existing guarantee (confidentiality, integrity, the N−2 collusion bound) or cost may regress. New properties can add cost, but we measure it rather than wave it away. Second, dropout handling has its own catch. We can have recovery, one-shot, or no extra setup, but only two of the three. Shamir reconstruction adds a round, threshold decryption needs key setup, and exclusion throws the dropped client's data away. Whichever we pick is a real trade, not a free choice.

## Directions, in rough priority order

**1. Cheaper, dropout-tolerant masking.** It hits the O(N) per-client cost and dropout at once without touching share-secrecy.

- A sparse mask graph has each client mask about log N neighbours instead of all N−1. The masks still cancel, the security still holds, and client compute drops. Lowest-risk win.
- Coded aggregate masks, in the style of LightSecAgg, let the server rebuild the combined mask from shares already uploaded, so a dropout costs no recovery round. The honest catch: this is no longer literal one-shot (LightSecAgg runs in about three rounds) and it adds encoding work on the client. Before committing, check that the coded reconstruction actually composes with MK-CKKS partial-decryption shares. LightSecAgg was designed for masks over plaintexts, and ours sit on the shares.

**2. Full post-quantum.** MK-CKKS is already quantum-safe. The ECDH masking is the weak link.

- ML-KEM takes over the mask-seed derivation. Run it once at setup and the one-round structure survives; it also forces fresh masks each round.
- ML-DSA replaces the classical signatures used for authentication and transport.
- It helps to separate two layers when we write this up: the protocol's own primitives, and the deployment stack around them (transport, auth, key distribution). End-to-end post-quantum needs both, and most papers only secure the first.
- The result is a security argument resting entirely on lattices, with the cost landing in setup and storage bytes rather than the per-round path.

**3. Payload compression.** The protocol expands ciphertext about 12× over plaintext, and that is the number reviewers look at.

- Slot packing groups several layers or blocks into one CKKS plaintext.
- Sparsification helps if it is compatible with aggregation. Rand-k and layer-level work; top-k does not.
- Add a small, adapter-sized run to the experiments. It widens the communication story and sets up the LoRA work later.
- Packing trades against noise, so confirm it stays inside the decode budget.

**4. Dropping the trusted setup.** The CRS may come out with a near-trivial change: let each client sample its own public element instead of sharing one. This looks safe because Hyb-Agg never forms a true combined multi-key ciphertext, but it needs a noise check against the library before we claim it.

**5. Input verification.** Exploratory, since the cost on a Pi is unknown. Lattice range proofs would let a client show its update is in range without revealing it, which defends against malicious clients. They are expensive on small devices, so the realistic scope is input validation only, with full Byzantine robustness left for later. A signature proves who sent an update, not that the update is well-formed, so it does not stand in for this.

## Experiments

**Datasets and utility.** Use real FL tasks (FEMNIST, Shakespeare, a LoRA fine-tuning task) instead of synthetic vectors. Check accuracy against plaintext FedAvg to confirm the crypto does not hurt the model, and verify exact recovery still holds under packing, post-quantum primitives, and whichever dropout mechanism we choose.

**Baselines and scaling.** Reimplement SecAgg, LightSecAgg, SASH, and xMK-CKKS on the same hardware, adding tMK-CKKS and FedSHE if time allows. Push the client count well past 500, and run ablations that isolate each piece.

**Cost.** Time each phase (keygen, encrypt, mask, aggregate, decode) against client count and model size. Track client and server storage against client count. Re-measure the expansion factor with packing, including a small adapter-sized point. Measure energy on the Pi.

**Mechanism-specific.** Sweep the dropout rate and confirm correctness, and for coded masks probe behaviour at and beyond the preset dropout budget. Microbenchmark ML-KEM and ML-DSA on the device. Show the sparse graph's per-client cost growing like log N rather than N. Measure range-proof cost only if we pursue verification.

## Where the proofs get hard

A few property pairs genuinely fight each other, and any plan to get everything at once breaks on one of them. Verifiability pulls toward per-client artifacts while unlinkable privacy pulls away. Traceability needs openable per-client tags, which is the same structure that leaks inputs. Recovery, one-shot, and setup-freeness form the dropout trilemma above. And the neat aggregate signatures like BLS are not post-quantum, while the post-quantum signature does not aggregate as cleanly.

## Out of scope

Lattice SNARKs for proving ciphertext well-formedness are still research-grade and will not run on a Pi, so a future-work mention is as far as that goes. Folding schemes cut proof cost but break one-shot. If we ever want machine-checked proofs, the tool is EasyCrypt, and only after the paper proofs are solid. A full BLS aggregate-signature contribution is out, since it works against the post-quantum direction.

## Parked

SaE, mask-free aggregation with cohort-authorized decryption, stays a negative result. In individual-key MK-CKKS, subtracting a dropout out of the sum needs ciphertexts that are individually openable, and those leak each client's input to an untrusted server. Getting share-secrecy back forces either an aggregate key (xMK-CKKS, which then cannot subtract a dropout cleanly) or threshold decryption (which needs setup). It earns a place in the paper precisely because it explains why the masking design is the right one, not as something to build.

LoRA fine-tuning is the next paper, not this one. Harden the protocol first, then apply it to federated fine-tuning of language models: FFA-LoRA freezes the A matrix so aggregation stays linear, with adapter packing and MKHE composition on top. Adapters are tiny, so the communication picture only improves. The open question is hardware. Can the target device actually run the local fine-tuning, holding the frozen base model and training the adapter? One test settles it: load a small base model with an adapter on the device and time a single step. The small-payload experiment above already lays the groundwork.

## The decision that comes first

Everything hangs on the server threat model. Semi-honest or malicious changes the masking, the dropout mechanism, and the post-quantum approach. Settle that, and most of the open choices resolve on their own.