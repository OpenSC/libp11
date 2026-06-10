# Forking `libp11` and opening a pull request

This guide takes the `no_login_cache` change from your local copy, publishes it
as a **fork** of [`OpenSC/libp11`](https://github.com/OpenSC/libp11), and opens a
**pull request** back to that project — **without needing write access** to it.

> **Terminology:** a **fork** is a copy of the repo under your account (here
> `dantecmelo/libp11`); a **branch** is a named line of commits inside a repo
> (here `session-fix`). They are not the same thing.

**Follow steps 1–12 in order.** They assume your goal is a pull request.
If instead you only want your own public fork **without** a PR, do steps 1–2 and
then see **Appendix A**. Throughout, replace `dantecmelo` with your GitHub
username and adjust file paths to your machine.

> **Two folders are involved:**
> - **Source (your edited copy):** `C:\Users\dante.melo\My Drive\_PS\Projects\MathWorks\libp11-no-deinit-fix`
> - **Clone (this folder, where you prepare the PR):** a fresh clone of your fork.

---

## 1. Install prerequisites

- A **GitHub account** (free).
- **git** — and optionally the **GitHub CLI** (`gh`), which simplifies auth and
  PR creation:

  | OS | Install git | Install gh (optional) |
  |----|-------------|------------------------|
  | **Debian / Ubuntu / WSL** | `sudo apt install git` | `sudo apt install gh` |
  | **macOS** | `xcode-select --install` (or `brew install git`) | `brew install gh` |
  | **Windows** | `winget install Git.Git` (or [git-scm.com](https://git-scm.com)) | `winget install GitHub.cli` |

  On **Windows**, run this guide's commands in **Git Bash** so the `bash`-style
  commands work; PowerShell variants are given where they differ.

- *(Optional, only if you want to build to sanity-check — step 7)* the libp11
  build toolchain. Debian/Ubuntu/WSL: `sudo apt install -y build-essential
  autoconf automake libtool pkgconf libssl-dev`. macOS: `brew install openssl@3
  autoconf automake libtool pkgconf`.

- **Set your commit identity** once:

  ```bash
  git config --global user.name  "Dante Melo"
  git config --global user.email "you@example.com"   # an email on your GitHub account
  ```
  The name is cosmetic; GitHub links commits to you by the **email**, so use a
  verified account email or your `…@users.noreply.github.com` address.

- **Choose how you'll authenticate** when pushing (used in step 9):
  - **GitHub CLI (easiest):** `gh auth login` stores credentials and configures git.
  - **Personal Access Token (PAT):** pasted as the *password* at the HTTPS prompt
    — your account password will **not** work (steps in step 9).
  - **SSH key:** `ssh-keygen -t ed25519 -C "you@example.com"`, then add
    `~/.ssh/id_ed25519.pub` at GitHub → *Settings → SSH and GPG keys*.

---

## 2. Create your fork

**Web UI:** open <https://github.com/OpenSC/libp11> → **Fork** → set **Owner** to
`dantecmelo`, keep the default repository name `libp11` → **Create fork**. You
now have `https://github.com/dantecmelo/libp11`.

**Or GitHub CLI:**
```bash
gh repo fork OpenSC/libp11 --clone=false
```

**(Optional) Set the fork's "About" description:**
```bash
gh repo edit dantecmelo/libp11 \
  --description "Fork of OpenSC/libp11 adding an opt-in no_login_cache provider parameter that releases the token login session on key free to avoid session-slot exhaustion on capped HSMs (e.g. YubiHSM 2)." \
  --add-topic openssl --add-topic pkcs11 --add-topic yubihsm
```

---

## 3. Clone your fork and add the upstream remote

A PR needs your branch to share history with OpenSC/libp11, so start from a
**clone of your fork** — **not** from your edited copy. Clone into a *new* folder:

```bash
git clone https://github.com/dantecmelo/libp11.git
cd libp11
git remote add upstream https://github.com/OpenSC/libp11.git
git fetch upstream
```

Run **all** the remaining git commands from inside this `libp11` folder. If git
prints `fatal: not a git repository`, you're in the wrong directory — `cd` back
into the clone. (Never run git inside your edited copy, and don't `git init` it.)

> **Already have a working clone** of libp11? Reuse it instead — see **Appendix B**.

---

## 4. Create your branch

Branch off the latest upstream `main` for the cleanest PR base:

```bash
git checkout -b session-fix upstream/main
```

---

## 5. Copy your changed files into the clone

Copy **only the files this change touches** from your edited copy into the clone.
The PR set is the **10 source files + `NEWS`**, plus the PR README
(`README.pr.md`, which is upstream's README + the `no_login_cache` docs) copied
in **as `README.md`**.

*Windows PowerShell:*
```powershell
$src = "C:\Users\dante.melo\My Drive\_PS\Projects\MathWorks\libp11-no-deinit-fix"
$files = @(
  "src\libp11-int.h",
  "src\p11_slot.c",
  "src\p11_rsa.c",
  "src\p11_ec.c",
  "src\p11_front.c",
  "src\libp11.h",
  "src\libp11.exports",
  "src\util.h",
  "src\util_uri.c",
  "src\provider_helpers.c",
  "NEWS"
)
foreach ($f in $files) { Copy-Item -Path (Join-Path $src $f) -Destination $f -Force }
Copy-Item -Path (Join-Path $src "README.pr.md") -Destination "README.md" -Force
```

*macOS / Linux / WSL / Git Bash:*
```bash
SRC="/path/to/libp11-no-deinit-fix"
for f in src/libp11-int.h src/p11_slot.c src/p11_rsa.c src/p11_ec.c \
         src/p11_front.c src/libp11.h src/libp11.exports src/util.h \
         src/util_uri.c src/provider_helpers.c NEWS; do
  cp "$SRC/$f" "$f"
done
cp "$SRC/README.pr.md" README.md   # PR README = upstream README + no_login_cache docs
```

> The fork-only files (`README.upstream.md`, `README.pr.md`, `FORK-AND-PR.md`,
> and your fork's own `README.md` with its fork note) are intentionally **not**
> copied into the clone — they don't belong in an upstream PR. To host a custom
> README on your fork separately, see **Appendix C**.

---

## 6. Verify the diff is exactly your change

```bash
git status
git diff --stat
```

Expected: the 10 `src/…` files, `NEWS`, and `README.md`. Spot-check the README:
```bash
git diff README.md     # ONLY the no_login_cache bullet + the env-var line
```
If `git diff` shows a "Fork note", an HTML comment, or `README.upstream.md` /
`README.pr.md`, those slipped in — remove them. If files you never touched show
changes, your copy is based on an older upstream — re-apply just your edits by
hand until the diff is clean.

---

## 7. (Optional) Build to confirm it compiles

**libp11 has no code-generation step for any file in this change** — unlike some
OpenSSL projects, you do **not** regenerate anything. The only build-system
touchpoint is the symbol exports list `src/libp11.exports`, which already
contains the new `PKCS11_set_no_login_cache` symbol. So you can commit as-is.

To sanity-check that it builds (needs the toolchain from step 1; this is a fresh
clone, so generate `configure` first):

```bash
./bootstrap                 # generate ./configure (git checkout, not a tarball)
./configure
make
# confirm the new public symbol is exported:
nm -D src/.libs/libp11.so | grep PKCS11_set_no_login_cache
```

---

## 8. Commit your change

```bash
git add -A
git status                 # review exactly what's staged
git commit -s -m "Add opt-in no_login_cache to release the token login session on key free

Signing with one short-lived process per file against a token with a hard
session limit (e.g. YubiHSM 2, 16 sessions) exhausts sessions: libp11 skips its
teardown at process exit (g_shutdown_mode set by the atexit handler), so the
cached login session is never released; and on the YubiHSM only C_Logout (not
C_CloseSession) frees the authenticated session.

This adds an opt-in 'no_login_cache' provider parameter and a public
PKCS11_set_no_login_cache() API. When set, the token is logged out and its
sessions are closed as soon as a private key object is freed (RSA/EC finish
callbacks), during normal runtime instead of at the skipped exit. Re-login
happens on the next key load. Behaviour is unchanged when the parameter is
unset."
```

The `-s` adds a `Signed-off-by` line (the **DCO** — Developer Certificate of
Origin). Check the repo's `CONTRIBUTING`/`COPYING` for whether it's required;
include `-s` if in doubt.

---

## 9. Push to your fork

```bash
git push -u origin session-fix
```

At the HTTPS prompt, enter username `dantecmelo` and paste a **Personal Access
Token as the password** — **your account password will not work.**

> **If you see `Invalid username or token. Password authentication is not
> supported…` / `Authentication failed`:**
>
> 1. **Create a token** — fine-grained (recommended):
>    <https://github.com/settings/tokens?type=beta> → **Generate new token** →
>    *Resource owner* `dantecmelo` → *Repository access* → only
>    `dantecmelo/libp11` → *Permissions → Contents: Read and write* →
>    **Generate**, then copy it (`github_pat_…`). Classic alternative:
>    <https://github.com/settings/tokens> → "Generate new token (classic)" →
>    scope `repo`.
> 2. **Push again** and paste the token at the `Password:` prompt (input hidden).
> 3. **Avoid re-prompts:** `git config --global credential.helper store` (caches
>    the PAT in `~/.git-credentials`, plaintext), or use the GitHub CLI:
>    `gh auth login && gh auth setup-git`.
>
> **SSH alternative:** add an SSH key (step 1), then
> `git remote set-url origin git@github.com:dantecmelo/libp11.git` and push.

Your branch is now at `https://github.com/dantecmelo/libp11/tree/session-fix`.

---

## 10. Open the pull request

**Web UI:** visit your fork — GitHub shows a **"Compare & pull request"** banner
for the new branch; click it (otherwise **Contribute → Open pull request**).
Confirm the direction:
- **base:** `OpenSC/libp11` · `main`
- **head:** `dantecmelo/libp11` · `session-fix`

Leave **"Allow edits by maintainers"** checked, add a title and description
(template below), then **Create pull request** (or the dropdown's **Create draft
pull request** to let CI run first).

**Or GitHub CLI:**
```bash
gh pr create --repo OpenSC/libp11 --base main \
  --head dantecmelo:session-fix \
  --title "Add opt-in no_login_cache to release the token login session on key free" \
  --body-file PR-BODY.md
# add --draft to open it as a draft
```

**Suggested PR description:**
```markdown
## Problem
Signing with one short-lived `openssl` process per file against a token with a
hard limit on concurrent authenticated sessions (notably the YubiHSM 2, max 16)
exhausts the sessions. Each process logs in and the login session is never
released, because libp11 skips its teardown at process exit — the
`g_shutdown_mode` guard set by the `atexit` handler in `util_uri.c` makes
`UTIL_CTX_free_libp11` skip `PKCS11_release_all_slots`/`C_Finalize`. On the
YubiHSM, `C_CloseSession` does not free the authenticated session — only
`C_Logout` does. After 16 files the 17th fails with "could not read private key".

## Change
Adds an opt-in `no_login_cache` provider parameter (and a public
`PKCS11_set_no_login_cache()` API). When set, the token is logged out and its
sessions are closed as soon as a private key object is freed (in the RSA/EC key
`finish` callbacks), during healthy runtime — not at the skipped exit. Re-login
happens automatically on the next key load.

## Safety / scope
- Opt-in: with the parameter unset, behaviour is byte-for-byte unchanged.
- The logout helper is self-contained (it does not call `pkcs11_wipe_cache` or
  `pkcs11_get_session`) to avoid re-entrancy from the key-free callback; it is
  idempotent via a lockless `logged_in` check, so it never recurses or nests
  `slot->lock`.
- Covers RSA and EC keys. EdDSA has no per-key finish callback in libp11, so it
  is out of scope (documented).

## Testing
Verified on a YubiHSM 2: a 50-iteration `openssl dgst -sha512 -sign` loop that
previously failed after the 16th now completes; a PKCS#11 trace shows one
`C_Logout` per key free.
```

---

## 11. After opening the PR

- **Respond to review** by pushing follow-up commits to the **same branch**
  (`git push origin session-fix`) — the PR updates automatically.
- **CI** runs on the PR; watch the checks and fix any failures.
- **Likely requests / things already done for this change:**
  - A test under `tests/` exercising the option (maintainers may ask for one).
  - **`NEWS` entry** — already added (top "unreleased" section).
  - **Doxygen comment** on the new public function — already added in `libp11.h`.
  - **Exported symbol** — already added to `src/libp11.exports`.
  - A possible design discussion about exposing a new public API
    (`PKCS11_set_no_login_cache`) vs keeping the flag internal. It is exposed
    publicly because `util_uri.c` already configures libp11 through public
    `PKCS11_*` calls (e.g. `PKCS11_set_ui_method`); that's the consistent layering.
  - A DCO `Signed-off-by` line if not already present.

---

## 12. Keep your fork up to date

If upstream moves on, rebase your branch onto the latest `main`:

```bash
git fetch upstream
git checkout main && git merge --ff-only upstream/main && git push origin main
git checkout session-fix
git rebase main                            # replay your commits on top; resolve conflicts
git push --force-with-lease origin session-fix
```

`--force-with-lease` updates the PR branch safely after a rebase without
clobbering anyone else's pushed changes.

---

## Appendix A — Publish your fork without a PR

If you just want your code on your own fork (no upstream PR), turn your edited
copy directly into a repo. Its history won't link to upstream — fine for a
personal copy, but no clean PR later (use the main flow for that).

```bash
cd "/path/to/libp11-no-deinit-fix"     # your edited copy
git init
git remote add origin https://github.com/dantecmelo/libp11.git
git add .                              # the bundled .gitignore keeps build junk out
git commit -m "no_login_cache: release the token login session on key free"
git branch -M session-fix
git push -u origin session-fix      # PAT as password — see step 9
```

Push to a **new branch** as shown, **not** `main` (your fork's `main` holds
upstream history; pushing unrelated history there would be rejected).

---

## Appendix B — Reuse an existing clone

If you already have a clone of libp11, use it instead of cloning fresh in step 3.
Point its remotes at your fork:

```bash
cd /path/to/your/libp11-clone
git remote rename origin upstream                 # was OpenSC/libp11 → now "upstream"
git remote add origin https://github.com/dantecmelo/libp11.git
git fetch upstream
git remote -v                                     # upstream=OpenSC, origin=your fork
```

Then continue at **step 4**.

**Linux ownership note:** if the clone was built under `sudo` and is root-owned,
git will refuse to use it. Fix once: `sudo chown -R "$USER":"$USER" <clone>` (or
`git config --global --add safe.directory <clone>`).

---

## Appendix C — Host a custom README / handle the fork-only files

Four files are **fork-only** and must stay **out of the PR**:
`README.upstream.md` (pristine upstream copy), `README.pr.md` (the PR README),
this `FORK-AND-PR.md`, and your edited copy's `README.md` (the one with the fork
note). The PR's `README.md` comes from `README.pr.md` (step 5), so don't copy the
others into the PR branch.

To show a custom README on your **fork's** page, commit the fork files to a
different branch so they never mix into the PR — e.g. on your fork's `main`:
```bash
git checkout main
# copy README.md (fork version), README.upstream.md, FORK-AND-PR.md in, then:
git add README.md README.upstream.md FORK-AND-PR.md
git commit -m "Fork-specific docs"
git push origin main
git checkout session-fix          # back to your PR branch
```

---

## Quick reference

| Action | Command |
|---|---|
| Create fork (CLI) | `gh repo fork OpenSC/libp11 --clone=false` |
| Clone fork + upstream | `git clone https://github.com/dantecmelo/libp11.git && cd libp11 && git remote add upstream https://github.com/OpenSC/libp11.git` |
| Create branch | `git checkout -b session-fix upstream/main` |
| Build (sanity check) | `./bootstrap && ./configure && make` |
| Commit (with DCO) | `git commit -s -m "…"` |
| Push to fork | `git push -u origin session-fix` |
| Open PR (CLI) | `gh pr create --repo OpenSC/libp11 --base main --head dantecmelo:session-fix` |
| Sync with upstream | `git fetch upstream && git rebase upstream/main` |
