# spake2 — vendored third-party SPAKE2 (curve25519)

Third-party implementation vendored source-in-repo, per README_AGENT §8:
only mature implementations, never hand-written crypto.

## Provenance

C port of **BoringSSL `crypto/curve25519/spake25519.cc`** (Copyright 2016
The BoringSSL Authors / Google, Apache-2.0) — the implementation Google
wrote for Intel SGX remote attestation and adb pairing. The M/N blinding
tables, the scalarmult ladder and the password-scalar cofactor hack are
byte-identical to upstream. The port is taken from
`MuntashirAl-Islam/spake2-c` (README: "fully compatible with the BoringSSL
implementation"), which is also what `3c71/spake2` integrates into Android.

Protocol shape: balanced SPAKE2 over curve25519 (Edwards representation),
two messages of 32 bytes each — matching the 火漆 two-frame pairing minimum
(README_AGENT §4). Key = SHA-512 over both names, both shares, the DH
result and the password hash.

## Files and licenses

| File | Origin | License |
|---|---|---|
| `spake2.c` | spake2-c port of BoringSSL spake25519.cc | ISC (Google 2020 / Muntashir 2021) |
| `spake2.h` | spake2-c | Apache-2.0 (Muntashir 2022) |
| `ed25519.h` | spake2-c (BoringSSL curve25519 internals + SUPERCOP ref10 public domain + Fiat) | ISC / public domain |
| `curve25519_32.h` | spake2-c (mit-plv/fiat-crypto) | MIT |
| `sha512.h` / `sha512.c` | written for 火漆 | AGPL-3.0-or-later (this project) |

## 火漆 integration changes vs upstream spake2-c

All listed here; protocol math untouched (host tests pin behaviour, and
`test_spake2.c` replicates the upstream BoringSSL test matrix).

1. **`rand()` → `randombytes_buf`** (spake2.c): the upstream port generated
   the private scalar from libc `rand()` — not a CSPRNG. This restores the
   BoringSSL original (`RAND_bytes`), routed through libsodium (§8 红线:
   只从操作系统 CSPRNG 取随机数). Also makes the scalar deterministic
   under the host-test RNG override.
2. **Error-path `printf()`s removed** (spake2.c): release builds carry no
   logs (§9).
3. **Include paths flattened**: `<spake2/*.h>` → `"*.h"`.
4. **`sha512.c` (glibc-derived, LGPL-2.1) dropped**: replaced by a fresh
   30-line shim (`sha512.h`/`sha512.c`) backing the same 3-call interface
   with libsodium's `crypto_hash_sha512`. The whole vendored set is now
   permissively licensed and links against the already-vendored libsodium.
5. **`SPAKE2_generate_msg_seeded` added** (spake2.c/h, 2026-11 公共会话):
   the original generate gained a static internal form whose private-scalar
   CSPRNG draw is replaced by a caller-supplied 64B seed, routed through the
   identical `sc_reduce` + cofactor pipeline — a seeded run is byte-equivalent
   to a CSPRNG run that happened to draw the seed, so the same (seed, 暗号)
   always reproduces the same 32B share (静态邀请码). No upstream math,
   signature or state machine changes; the public wrapper keeps its original
   CSPRNG behaviour. Pinned by `test_spake2.c` (determinism, cross-seed
   divergence, standard-responder interop) and by the `public_gate` section
   of `docs/vectors.json` (which also self-checks that the seeded path draws
   ZERO entropy). Caller discipline: the seed is 64B CSPRNG output captured
   once at gate creation, NEVER derived from the 暗号 (§8: a 暗号-derived
   scalar would turn leakage into impersonation). The upstream security
   proof requires the scalar to be uniform and secret — never fresh — so
   a persisted scalar preserves every SPAKE2 assumption (offline guessing
   stays infeasible; per-client keys stay independent because the client
   side still draws a fresh ephemeral).

## Security notes (honest boundaries)

- **No built-in key confirmation** (upstream design): both sides derive
  keys immediately; wrong passwords surface at the first AEAD message.
  火漆 composes a confirmation ON TOP (never modifies the library):
  the reply frame carries `HKDF-Expand(pake_raw, "confirm", 32)` so the
  inviter detects a wrong 暗号 at `swx_session_finish`; the responder
  is confirmed implicitly by the inviter's first decryptable message.
- **Shares are Edwards point encodings**, not uniform strings: a random
  32-byte string decodes as a valid point with probability ≈ 1/2, so the
  pairing frames carry ~1 bit of statistical structure each (likelihood
  ratio ~2 per message) — far weaker than the retired deterministic
  `SWX1` magic prefix, but not literally zero. Uniform shares would need
  an Elligator map, which no mature C implementation provides.
- **Online guessing only**: an active attacker must run a full pairing
  interaction per 暗号 guess (SPAKE2's core property; offline dictionary
  attacks against captured shares are infeasible).
