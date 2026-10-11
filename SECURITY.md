# Security

Only the latest release receives security fixes.

## Report a vulnerability

Report privately through [GitHub](https://github.com/christosdaggas/PeekIn/security/advisories/new)
or email <info@chrisdaggas.com> with the subject **PeekIn security**.

Include your PeekIn version (`peekin version`), distribution, camera and steps
to reproduce. Expect a reply within a week. Please allow time for a fix before
publishing details.

Report authentication bypasses, wrong-account matches, broken password fallback,
face login working where disabled, unauthorized file access or leaked face data.

## Known limitations

- Head-turn checks are not certified liveness detection. Interactive video
  replays and masks may pass; without the check, photos may pass on colour cameras.
- Three left/right turns give only eight sequences; a recording can match one.
- Look-alikes may match. On the LFW photo dataset, the default threshold accepted
  about 1 in 240 stranger attempts against a five-sample model. This is not a
  measured webcam login rate.
- Root can read or replace face models.
- Without a TPM, the encryption key is on the same disk, so a full disk copy
  can decrypt the models. A backup excluding `/var/lib/systemd/credential.secret`
  cannot decrypt host-key-encrypted models on its own.
- Model encryption alone does not protect a whole machine booted from other
  media. Use full-disk encryption for disk protection.

See the [README](README.md#security-and-privacy) and
[threshold measurements](docs/THRESHOLDS.md) for details.
