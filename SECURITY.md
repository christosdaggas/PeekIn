# Security policy

PeekIn is part of the login path, so security reports get priority.

## Reporting a vulnerability

Please report privately, not in a public issue:

- through GitHub's "Report a vulnerability" button on the repository's
  Security tab, or
- by e-mail to info@chrisdaggas.com with "PeekIn security" in the subject.

Include the version (`peekin version`), the Fedora version, the camera,
and the steps to reproduce. You will get an answer within a week. Please give
us time to release a fix before publishing details.

## What counts

- Getting past face authentication without the enrolled face, or getting a
  face accepted for the wrong account.
- The password no longer working, or face authentication being used where it
  is switched off.
- Privilege problems: the PAM module, the polkit helper or the recognition
  worker doing more than they should, or reading or writing files they should
  not.
- Leaks of face models or other private data.

## Known limits (not vulnerabilities)

These are documented in the README and docs/THRESHOLDS.md:

- The head-movement check is not certified presentation-attack detection: an
  interactive video replay or a mask may pass it. Without it, a photo of the
  user may pass with a colour camera.
- A video of the user turning their head passes the head-movement check if it
  is cut to the turns asked for, or replayed until its own turns come up: PAM
  shows the whole sequence before the scan, and there are only 8 orders.
- Face recognition accepts some strangers: about 1 in 240 matches a 5-sample
  face model at the default threshold (measured on LFW; see
  docs/THRESHOLDS.md), more often for relatives and look-alikes.
- Someone with root access can read or replace face models.
- The encryption of face models at rest (TPM and host key) does not protect
  against someone who has the whole machine and boots it from other media;
  see the README's security section.
- Without a TPM the key is the host key on the same disk, so a full copy of
  the disk can decrypt the face models (a backup that leaves out
  `/var/lib/systemd/credential.secret` cannot).

## Supported versions

Only the latest release receives security fixes.
