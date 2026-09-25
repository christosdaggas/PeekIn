# Distributing PeekIn through COPR

COPR builds the RPMs on Fedora's build service and publishes them as a `dnf`
repository, so users install and update with `dnf` instead of building RPMs
themselves. The repository already contains everything COPR needs:

- `.copr/Makefile`: the "make srpm" entry point. COPR runs it as root in a
  Fedora chroot with network access. It calls `packaging/build-rpm.sh` with
  `SRPM_ONLY=1`, which vendors all Rust crates and downloads the two face models
  (checked against their SHA-256 sums), so the binary build itself runs
  offline.
- `packaging/peekin.spec`: the spec file. It also produces
  `peekin-debuginfo` and `peekin-debugsource`.

CI runs the same `make -f .copr/Makefile srpm` on every push and checks the
resulting source RPM.

## One-time setup (maintainer)

This needs a Fedora account. Nothing below can be done from the repository.

1. Create a Fedora account at <https://accounts.fedoraproject.org> and log in
   to <https://copr.fedorainfracloud.org> with it.
2. **New Project**:
   - Project name: `peekin`
   - Chroots: `fedora-44-x86_64`. Add `fedora-rawhide-x86_64` to catch the next
     release early. The package also builds for `aarch64` in principle, but
     it has not been tested there.
   - "Enable internet access during builds" is not needed: the source RPM
     already contains everything.
3. In the project: **Packages → New package**, source type **SCM**:
   - Clone URL: `https://github.com/christosdaggas/PeekIn.git`
   - Committish: `main` (or leave it empty for the default branch)
   - Subdirectory: empty
   - Spec file: `packaging/peekin.spec`
   - Type: Git
   - SRPM build method: **make srpm**
   - Tick **Auto-rebuild**.
4. Start the first build with **Rebuild** on the package page.
5. Optional: rebuild on every push. Under the project's **Settings →
   Integrations**, copy the GitHub webhook URL. In the GitHub repository go to
   **Settings → Webhooks → Add webhook**, paste it, choose content type
   `application/json` and "Just the push event".

## Releases

`dnf` only upgrades when the version or release changes. Bump `Version` (with
the crate versions, which `build-rpm.sh` checks) or `Release` in the spec, with
a `%changelog` entry, for every build users should receive. A rebuild of an
unchanged `Version-Release` is not offered as an update.

## For users

Replace `OWNER` with the Fedora account name that owns the project:

```sh
sudo dnf copr enable OWNER/peekin
sudo dnf install peekin
sudo peekin doctor
```

Updates then arrive with `sudo dnf upgrade`. For crash reports, install the
debug packages as well, so `coredumpctl gdb` shows function names and source
lines:

```sh
sudo dnf install peekin-debuginfo peekin-debugsource
```
