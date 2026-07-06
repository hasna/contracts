# Hasna Open Source Licensing Policy

Status: active — approved 2026-07-06 (OSS cloud migration gate `97610c99`, item **d**).
Owner: Hasna, Inc.

This document is the source of truth for which license a Hasna repository ships
under. It applies across the `hasna/opensource/open-*` repositories and the SaaS
platform repositories.

## TL;DR

| Repo class | License | Notes |
| --- | --- | --- |
| **New** `open-*` OSS repos | **FSL-1.1-Apache-2.0** | Fair Source: competing-use restricted, auto-converts to Apache-2.0 two years after each version is published. |
| **Existing** `open-*` OSS repos | **Unchanged** | Keep their current license (mostly Apache-2.0) until each is individually re-decided. No bulk relicense. |
| SaaS / platform repos | **Proprietary** | Not open source. `platform-*` and hosted-service code stays closed. |

## 1. New OSS repositories ship FSL-1.1-Apache-2.0

Every **newly created** `open-*` repository ships under the **Functional Source
License, Version 1.1, with an Apache 2.0 future license** (`FSL-1.1-Apache-2.0`),
the same Fair Source model used by Sentry.

What FSL-1.1-Apache-2.0 means in practice:

- **Permitted:** internal use, modification, redistribution, non-commercial
  education and research, and use within professional services you provide to a
  licensee. In short — everything except competing with us.
- **Restricted (Competing Use):** you may not make the Software available to
  others in a commercial product or service that substitutes for the Software,
  substitutes for another product/service we offer built on the Software, or
  offers substantially the same functionality.
- **Auto-conversion:** each published version automatically becomes available
  under the **Apache License, Version 2.0** on the **second anniversary** of the
  date that version was made available. The restriction is time-boxed, not
  perpetual.

The canonical license text to stamp into a new repo lives at
[`docs/licenses/FSL-1.1-Apache-2.0.txt`](./licenses/FSL-1.1-Apache-2.0.txt).
Copy it to the repo root as `LICENSE`, keeping the `Copyright <year> Hasna, Inc.`
notice line. Set the package manifest license field to `FSL-1.1-Apache-2.0`
(a valid SPDX Fair Source identifier).

## 2. Existing OSS repositories keep their current license

Repositories that already exist under `hasna/opensource/open-*` (for example
`open-contracts`, currently Apache-2.0) **keep their current license**. There is
**no bulk relicense**. Any move from Apache-2.0 to FSL for an existing repo is a
per-repo decision recorded separately, because relicensing already-published
Apache-2.0 code does not retroactively restrict versions already released under
Apache-2.0.

## 3. SaaS / platform repositories stay proprietary

Hosted-service and platform code (`platform-*` and the live SaaS plane) is **not
open source** and stays **proprietary**. FSL is for source-available product
libraries and CLIs, not for the hosted control planes.

## 4. How the license is applied to a new repo

New `open-*` repos are generated from the Hasna open-source scaffold, which
stamps the `LICENSE` file verbatim into the new repo.

- Scaffold source (as of 2026-07-06):
  `github.com/hasnaxyz/scaffold-open-source`, local checkout
  `workspace/hasnaxyz/scaffold/scaffold-open-source`.
- The stamped template file is `template/LICENSE` in that repo; `src/generate.ts`
  copies it verbatim (no token substitution) so the `Copyright <year> Hasna, Inc.`
  notice ships as-is.
- The scaffold's `template/LICENSE` and `template/package.json` `license` field
  are set to `FSL-1.1-Apache-2.0` so every newly scaffolded repo is Fair Source
  by default.

If you create a repo by hand (not via the scaffold), copy
`docs/licenses/FSL-1.1-Apache-2.0.txt` to `LICENSE` and set the manifest
`license` field to `FSL-1.1-Apache-2.0`.
