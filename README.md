# Sealing Wax

[简体中文](README_ZH.md) | English | [AI collaboration doc](README_AGENT.md)

> Encryption that follows the user, not the other way around.

**Sealing Wax** is an end-to-end encrypted session layer that runs on top of the
instant messengers you already use. Messages are sealed on your device, travel
through the IM as ciphertext, and are opened only on the other side — the server
never sees a key, and never sees a plaintext byte.

- **No server, no account, no cloud** — there is no backend at all: nothing to
  register, nothing to raid
- **Ephemeral by default** — an unsaved session writes zero bytes to disk; leave
  the chat, and it never existed
- **Both ends equal** — no organization, no administrator, no policy gate; each
  key belongs to exactly one conversation
- **Unrecognizable traffic** — pairing frames and data frames are
  indistinguishable from random bytes on the wire

## How to use

### Pair once (per conversation)

1. **Side A** — tap **＋ New session**, enter a passphrase only the two of you
   know, copy the invite code, send it over the IM
2. **Side B** — tap **Join session**, paste the invite code, enter the same
   passphrase, copy the reply code, send it back
3. **Side A** — paste the reply code; pairing completes on paste and the chat
   opens

The passphrase should be a fact the two of you remember from real life — not
something you once typed in a chat. A wrong passphrase always fails the
handshake; retrying costs one new reply code, nothing else.

### Chat

- **Send** — type, tap **Encrypt & copy**, paste into the IM. One extra tap
  over a normal message; that is the entire cost of encryption here
- **Receive** — copy the ciphertext in the IM, switch back; the message
  decrypts itself on paste
- **Files** — pick a file, share the sealed `.swx` to the IM; the recipient
  imports it and exports the original wherever they choose
- **Verify** — a 9-digit code sits in the chat header at all times; read it
  aloud, or scan its QR code with the other side. If it does not match, someone
  is in the middle — stop using the session

### Keep it, or let it burn

Leaving a chat asks one question: save this session or not. Save it, and it
becomes a name on your home screen — tap and chat, no ceremony, no re-pairing.
Don't, and every trace is gone. Deleting a saved session destroys key and
history together, permanently.

### Public sessions (optional)

One switch turns a session into a door: a static invite code you can pin in
your profile bio. Anyone who knows the passphrase can knock, and each of them
gets a separate private conversation with you. Delete the public session, and
the door is gone; established conversations are untouched.

## How it works

Short version: the two devices agree on a key the IM can never learn, then use
it to seal every message.

- **Pairing** runs SPAKE2, a password-authenticated key exchange. The passphrase
  never crosses the wire; a man-in-the-middle relaying both codes cannot derive
  the key, and a wrong passphrase fails the handshake instead of producing a
  broken key
- **Messages** are sealed with ChaCha20-Poly1305 under keys derived through
  HKDF-SHA256 — fresh for every message and every direction; replayed or
  reordered frames are rejected by lifetime sequence numbers
- **Traffic shape** — every frame is masked, so what the IM carries is
  computationally indistinguishable from random bytes: it cannot tell Sealing
  Wax traffic from noise, let alone read it
- **Storage** — plaintext exists only in memory and on screen. Saved sessions
  keep their keys in an Android Keystore-backed envelope; unsaved sessions keep
  nothing at all

The full wire protocol is specified in [docs/wire-spec.md](docs/wire-spec.md)
with test vectors.

## Honest boundaries

A security tool that hides its limits is a liability.

**Protected against**: the IM server and any network observer — reading,
altering, forging, replaying, or relaying your messages. A pairing relay fails
the passphrase check; the 9-digit code in the chat header is a lifetime identity
dashboard.

**Not protected against**:

- A fully compromised, unlocked device — forensic tools may open saved sessions
- Communication metadata — who talks to whom, when, and how big; your IM
  already collects that
- A betraying counterpart — photos, screenshots, or a modified client keep the
  plaintext; no end-to-end tool can change this

And the passphrase is the weakest link: a low-entropy one shrinks the
online-guessing surface. PAKE forces every guess to happen online, one try at
a time — but a shared memory still beats a short word.

## Getting the app

Build from source: clone the repository and run `./gradlew assembleDebug`
(Android SDK required); CI builds the APK on every push. Prebuilt releases
will appear once v1 is ready.

## ⚠️ Disclaimer

- **Purpose limitation**:
  This project is intended for lawful personal communication, privacy
  protection, security research, and educational purposes only. Cryptography
  may be regulated in your jurisdiction; complying with local law is solely
  your responsibility. Do not use this project for any illegal purpose.

- **No audit, no guarantees**:
  This software has not undergone a formal third-party security audit. The
  design and implementation are offered in good faith, with the full source
  code available for public review — but the absence of vulnerabilities is
  neither claimed nor implied.

- **Device protection is best-effort**:
  Device-level safeguards (Keystore envelope, guarded memory, screenshot
  blocking, zero-state exit) are best-effort measures, not a promise of
  resistance against a seized, unlocked device or a capable forensic
  adversary. Do not bet life-critical secrets on any app.

- **Data loss is part of the design**:
  Unsaved sessions vanish when you leave them — a crash, a force-stop, or a
  plain exit destroys the keys: by design, not by accident. Deleting a saved
  session is irreversible. Sealed files (`.swx`) live in your IM: once the IM
  purges them, they are gone — only a name and a fingerprint remain locally.
  Changing devices loses every saved session, because keys never leave the
  device. Back up whatever you cannot afford to lose.

- **Third-party platforms**:
  This tool rides on instant messengers you do not control. An IM may filter,
  truncate, or delay large messages; its terms of service, and your local law,
  apply to everything you send through it. The developer is not responsible
  for account restrictions or any other consequence imposed by a third-party
  platform.

- **No warranty**:
  This software is provided under the terms of the AGPL-3.0-only license,
  **without any express or implied warranties**, including but not limited to
  the warranties of merchantability, fitness for a particular purpose, and
  non-infringement.

- **Limitation of liability**:
  To the fullest extent permitted by applicable law, **in no event shall the
  author or contributors be liable** for any direct, indirect, incidental,
  special, or consequential damages arising out of or in connection with the
  use or inability to use this software, including but not limited to data
  loss, legal consequences, or security incidents, even if advised of the
  possibility of such damages.

- **User responsibility**:
  Users assume all legal responsibilities arising from the use of this project,
  and from obtaining it from any channel.

- **Final interpretation**:
  The final interpretation of this disclaimer belongs to the author of this
  project.

## 🚫 Non-Commercial Statement

This project was started by the developer out of personal interest and is
**non-commercial** in nature:

- **Permanently free**: no paid features, memberships, subscriptions, or
  in-app purchases
- **No sponsorship channels**: the author has never opened sponsorship channels
  and accepts no donations of any kind
- **Research & privacy-oriented**: positioned as a personal-privacy research
  tool, not a commercial product

**License is AGPL-3.0-only — no commercial exceptions.** This project is
offered under the terms of the GNU Affero General Public License v3.0 only
(see [LICENSE](LICENSE)), and **every use must comply with that license in
full**. What AGPL requires — source availability, the same license for
derivatives, and offering the source to users of network services — is exactly
what it means to use this project. **Commercial use that cannot accept AGPL
terms does not have the author's authorization**: the author does not offer,
and will not negotiate, dual licensing, commercial exceptions, or proprietary
redistribution. Reselling builds for profit while ignoring AGPL obligations
is copyright infringement.

- **Attribution and statement integrity**:
  Redistribution of unmodified builds is permitted only together with this
  statement and proper attribution. **Removing, altering, or obscuring this
  non-commercial statement when redistributing is prohibited.**

- **Official channels only**:
  Obtain the app **only** from this repository (GitHub) or its official
  Releases. Builds from any other source are unofficial, unverified, and used
  entirely at the downloader's own risk. The developer assumes no
  responsibility for any issues arising from unofficial sources, and
  **reserves the right to pursue legal remedies against violations of the
  above terms**.

## 🙏 Acknowledgements

- [libsodium](https://github.com/jedisct1/libsodium) (ISC)
- [spake2-c](https://github.com/MuntashirAl-Islam/spake2-c) — C port of
  BoringSSL's SPAKE2 (ISC / Apache-2.0 / MIT)
- [Jetpack Compose](https://developer.android.com/compose) + Material 3
  (Apache-2.0)
- [Tink](https://github.com/tink-crypto/tink-java) (Apache-2.0)
- [ZXing](https://github.com/zxing/zxing) (Apache-2.0)

## 💬 Feedback

Issues, suggestions, and bug reports are welcome via GitHub Issues.

If you are contributing to this project (especially with AI assistance), read
[README_AGENT.md](README_AGENT.md) first — it carries the project's design
invariants and hard red lines. Skipping it and editing code directly is very
likely to break the zero-state core.

## ⭐ Support the Project

If this tool earns a place in your daily conversations, consider giving it a ⭐
on GitHub. Your recognition is what keeps an independent, non-commercial
project alive.
