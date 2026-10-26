# Synthetic examples and their assumptions

These are independent teaching models of ideal symbolic operations. They make
no claims about a named product, standard, implementation, or vulnerability.
The attacker controls the public network. Private keys remain uncompromised;
there are no computational, side-channel, guessing, or parser guarantees.

| Example | Reference obligation | Deliberate change | Independent audit |
|---|---|---|---|
| Message | Acceptance requires a prior honest signed message | Omit signature verification | Remove verification action |
| Replay | Signed reply matches the current fresh challenge | Retain signature verification but omit nonce matching | Remove nonce equality |
| Secrecy | Encrypt secrets only to the configured recipient | Accept an attacker-selected encryption key | Remove recipient-key equality |

Message authentication does not establish freshness, uniqueness, receiver
identity, or sender intent. The signing service is honest and its private key
is never revealed. The weakened case must falsify authentication while its
acceptance witness remains reachable.

The replay model allows unbounded challenges and an honest signer that signs
any supplied nonce. The reference binds an accepted response to the challenge
being answered. Both profiles verify `response_origin`: the nonce-check mutant
still requires a valid signature. Its freshness and cross-challenge replay
properties fail, separating key possession from response freshness. No claim
of intended peer identity or relay prevention is made.

The secrecy example has unbounded recipients and secret messages. The reference
checks the supplied encryption key against the intended recipient's key. Its
execution witness requires an honest receive. The mutant can still deliver
honestly but also encrypt to an attacker-selected key, breaking recipient binding
and secrecy. This models ideal public-key encryption and a trusted configured
key; it does not model certificate discovery or transport encryption.

All three mutation experiments start from a proved reference and independently
remove one check from the completed theory. A successful audit requires every
designated property to falsify while the stated execution witness still verifies.
