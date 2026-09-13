# Security Policy

`dsh-security` is a security-check framework for the DeepSeek Harness (DSH) ecosystem. Because a
security tool is itself part of the attack surface, we treat reports about **this** code with the same
priority we ask plugin authors to treat theirs.

## Reporting a vulnerability

**Preferred — GitHub private vulnerability reporting (enabled on this repository):**

<https://github.com/moonquake2004/dsh-security/security/advisories/new>

Reports filed there are visible only to the maintainer until an advisory is published. Please include
the affected version, a minimal reproduction, and the impact you believe it has.

**If you cannot use that channel**, open a *content-free* public issue ("requesting a security
contact") with no technical detail, and we will move the conversation to a private channel. Please do
not describe the issue in public.

## Scope

In scope:

- `dsh-security`'s own checks, protocol/envelope handling, and integrations.
- **False negatives** — a check that stays silent when it should fire. We treat these as
  vulnerabilities of the tool, not merely bugs. The project's worst historical failure was exactly
  this class: checks that could never match because a session-format change moved the fields, so the
  report read "clean" while the layer was blind.
- **False positives that make operators ignore the tool** — a check that cries wolf trains people to
  skip it. Please report those too; several were fixed this way.
- Any way our checks can be made to read or execute attacker-controlled code.

Out of scope (but we will relay it — see below): issues in the DSH host itself or in third-party
plugins. Those belong to their respective maintainers.

## Our own practice

- **We coordinate before publishing.** Anything we find in the host or in a third-party plugin is
  reported to the relevant maintainer first; we do not publish exploit detail ahead of a fix.
- **We do not publish unverified findings.** Claims in our checks, docs, and community posts carry the
  evidence we actually ran; what we could not verify is labelled as such.
- **We practise the disclosure hygiene we ask for** — private vulnerability reporting is enabled here
  and on `dsh-doctor`, and we follow the same channel when reporting to others.

## If your plugin is flagged

Our checks aim to be specific, and they explain *why* something fired. If a finding is wrong, please
open an issue with the input that produced it — a well-argued false positive is a real contribution
here, and the fix usually comes with a regression fixture.

## Supported versions

Security fixes are issued for the latest published minor line. Older lines may receive a note rather
than a patch; we will say which in the advisory.
